package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/miekg/pcap"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
)

type Frame struct {
	FrameID   uint16
	LastChunk uint16
	Data      []byte
}

var TotalFrames = 0

func main() {
	interf := flag.String("interface", "eth0", "What interface the device is attached to")
	debug := flag.Bool("debug", false, "Print loads of debug info")
	output := flag.String("output", "mkv", "Type of output")
	audio := flag.Bool("audio", true, "Output audio into MKV as well")
	ar := flag.Int("ar", 48000, "Audio sample rate")
	delay := flag.Float64("delay", 0.5, "Video-audio delay in seconds")
	heartbeat := flag.Bool("heartbeat", true, "Send packets needed to start/keep the sender transmitting")
	processhb := flag.Bool("processhb", false, "Process heartbeats from sender")
	senderip := flag.String("sender-ip", "192.168.168.55", "The IP address of the sender unit")
	flag.Parse()

	audiodis := make(chan []byte, 100)
	videodis := make(chan []byte, 100)

	if *ar != 44100 && *ar != 48000 {
		log.Fatalf("Invalid audio sample rate, only 44100/48000 allowed.")
	}

	if *output == "mkv" {
		go WrapinMKV(videodis, audiodis, *audio, *ar, *delay)
	} else if *output == "video" {
		*audio = false
		go DumpChanToFile(videodis, os.Stdout)
	} else if *output == "audio" {
		*audio = true
		go DumpChanToFile(audiodis, os.Stdout)
	} else {
		log.Fatalf("Invalid output value, only video/audio/mkv allowed.")
	}

	h, err := pcap.OpenLive(*interf, 1500, true, 500)
	if h == nil {
		log.Fatalf("Unable to capture %s: %s", *interf, err.Error())
	}
	err = h.SetFilter(fmt.Sprintf("host %s", *senderip))
	if err != nil {
		log.Fatalf("Unable to setup BPF: %s", err.Error())
	}
	defer h.Close()

	if *heartbeat {
		go BroadcastHeartbeat(*senderip)
	}

	droppedframes := 0
	desyncframes := 0

	CurrentPacket := Frame{}
	CurrentPacket.Data = make([]byte, 0)

	videodis <- []byte("--myboundary\nContent-Type: image/jpeg\n\n")

	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			// Timeout, continue
			continue
		}

		ApplicationData := pkt.Data[42:]

		// Maybe there is some audio data?
		if pkt.Data[36] == 0x08 && pkt.Data[37] == 0x12 && *audio {
			select {
			case audiodis <- ApplicationData[16:]:
			default:
			}

			continue
		}

		if pkt.Data[36] == 0xbe && pkt.Data[37] == 0x31 {
			if *processhb {
				ProcessHeartbeat(ApplicationData)
			}
			continue
		}

		// Check that the port is 2068
		if pkt.Data[36] != 0x08 || pkt.Data[37] != 0x14 {
			continue
		}

		FrameNumber := uint16(0)
		CurrentChunk := uint16(0)

		buf := bytes.NewBuffer(ApplicationData[:2])
		buf2 := bytes.NewBuffer(ApplicationData[2:4])
		binary.Read(buf, binary.BigEndian, &FrameNumber)
		binary.Read(buf2, binary.BigEndian, &CurrentChunk)

		if CurrentPacket.FrameID != FrameNumber && CurrentPacket.FrameID != 0 {
			// Did we drop a packet ?
			droppedframes++
			if CurrentPacket.FrameID < FrameNumber {
				CurrentPacket = Frame{}
				CurrentPacket.Data = make([]byte, 0)
				CurrentPacket.LastChunk = 0
				log.Printf("Dropped packet because of non sane frame number (%d dropped so far)", droppedframes)
			}
			continue
		}

		if *debug {
			log.Printf("%d/%d - %d/%d - %d", FrameNumber, CurrentChunk, CurrentPacket.FrameID, CurrentPacket.LastChunk, len(ApplicationData))
		}

		if CurrentPacket.LastChunk != 0 && CurrentPacket.LastChunk != CurrentChunk-1 {
			if uint16(^(CurrentChunk << 15)) != 65534 {
				log.Printf("Dropped packet because of desync detected (%d dropped so far, %d because of desync)",
					droppedframes, desyncframes)

				log.Printf("You see; %d != %d-1",
					CurrentPacket.LastChunk, CurrentChunk)

				// Oh dear, we are out of sync, Drop the frame
				droppedframes++
				desyncframes++
				CurrentPacket = Frame{}
				CurrentPacket.Data = make([]byte, 0)
				CurrentPacket.LastChunk = 0

				continue
			}
			CurrentPacket.LastChunk = CurrentChunk
		}

		CurrentPacket.Data = append(CurrentPacket.Data, ApplicationData[4:]...)

		if uint16(^(CurrentChunk >> 15)) == 65534 {
			// Flush the frame to output

			fin := []byte("\n--myboundary\nContent-Type: image/jpeg\n\n")
			fin = append(fin, CurrentPacket.Data...)
			select {
			case videodis <- fin:
			default:
			}

			TotalFrames++

			if *debug {
				log.Printf("Size: %d", len(CurrentPacket.Data))
			}

			CurrentPacket = Frame{}
			CurrentPacket.Data = make([]byte, 0)
			CurrentPacket.FrameID = 0
			CurrentPacket.LastChunk = 0
		}

	}
}

func WrapinMKV(videoin chan []byte, audioin chan []byte, audio bool, ar int, delay float64) {
	var ffmpeg *exec.Cmd

	if audio {
		ffmpeg = exec.Command("ffmpeg", "-nostdin", "-f", "mjpeg", "-i", "pipe:3", "-f", "s32be", "-ac", "2", "-ar", strconv.Itoa(ar), "-itsoffset", strconv.FormatFloat(delay, 'f', -1, 64), "-i", "pipe:0", "-f", "matroska", "-codec", "copy", "pipe:1")
	} else {
		ffmpeg = exec.Command("ffmpeg", "-nostdin", "-f", "mjpeg", "-i", "pipe:3", "-f", "matroska", "-codec", "copy", "pipe:1")
	}

	ffmpegstdout, err := ffmpeg.StdoutPipe()
	if err != nil {
		log.Fatalf("Unable to setup pipes for ffmpeg (stdout)")
	}

	audiofile, err := ffmpeg.StdinPipe()
	if err != nil {
		log.Fatalf("Unable to setup pipes for ffmpeg (stdin)")
	}

	pipe3r, videofile, err := os.Pipe()
	if err != nil {
		log.Fatalf("Unable to setup pipes for ffmpeg (video)")
	}

	ffmpeg.Stderr = os.Stderr
	ffmpeg.ExtraFiles = []*os.File{pipe3r}

	go DumpChanToFile(audioin, audiofile)
	go DumpChanToFile(videoin, videofile)

	if err := ffmpeg.Start(); err != nil {
		log.Fatalf("Unable to start ffmpeg: %s", err.Error())
	}

	if err := pipe3r.Close(); err != nil {
		log.Fatal("Unable to close read end of pipe")
	}

	for {
		_, err := io.Copy(os.Stdout, ffmpegstdout)
		if err != nil {
			log.Fatalf("unable to read to stdout: %s", err.Error())
		}
	}
}

func DumpChanToFile(channel chan []byte, file io.WriteCloser) {
	for blob := range channel {
		buf := bytes.NewBuffer(blob)
		_, err := io.Copy(file, buf)
		if err != nil {
			log.Fatalf("unable to write to pipe: %s", err.Error())
		}
	}

	log.Fatalf("Channel closed")
}
