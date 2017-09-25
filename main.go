package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/miekg/pcap"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
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
	output := flag.String("output", "video", "Type of output")
	audio := flag.Bool("audio", false, "Output audio into MKV as well")
	heartbeat := flag.Bool("heartbeat", true, "Send packets needed to start/keep the sender transmitting")
	senderip := flag.String("sender-ip", "192.168.168.55", "The IP address of the sender unit")
	flag.Parse()


	var videowriter *os.File
	pipename := randString(5)
	audiodis := make(chan []byte, 100)
	videodis := make(chan []byte, 100)

	if *heartbeat {
		go BroadcastHeartbeat(*interf, *senderip)
	}

	if *output == "mkv" {
		go WrapinMKV(fmt.Sprintf("/tmp/hdmi-Vfifo-%s", pipename), audiodis, *audio)

		err := syscall.Mkfifo(fmt.Sprintf("/tmp/hdmi-Vfifo-%s", pipename), 0664)
		if err != nil {
			log.Fatalf("Could not make a fifo in /tmp/hdmi-Vfifo-%s, %s", pipename, err.Error())
		}

		videowriter, err = os.OpenFile(fmt.Sprintf("/tmp/hdmi-Vfifo-%s", pipename), os.O_WRONLY, 0664)
		if err != nil {
			log.Fatalf("Could not open newly made fifo in /tmp/hdmi-Vfifo-%s, %s", pipename, err.Error())
		}
		go DumpChanToFile(videodis, videowriter)
	} else if *output == "video" {
		videowriter = os.Stdout
		go DumpChanToFile(videodis, videowriter)
	} else if *output == "audio" {
		videowriter = os.Stdout
		*audio = true
		go DumpChanToFile(audiodis, videowriter)
	} else {
		log.Fatalf("Invalid output value, only video/audio/mkv allowed.")
	}

	h, err := pcap.OpenLive(*interf, 1500, true, 500)
	if h == nil {
		fmt.Fprintf(os.Stderr, "de hdmi: %s\n", err)
		return
	}
	err = h.SetFilter(fmt.Sprintf("host %s", *senderip))
	if err != nil {
		log.Fatalf("Unable to setup BPF")
	}
	defer h.Close()

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
			ProcessHeartbeat(ApplicationData)
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

func randString(n int) string {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func WrapinMKV(uuidpath string, audioin chan []byte, audio bool) {
	var ffmpeg *exec.Cmd
	if audio {
		ffmpeg = exec.Command("ffmpeg", "-f", "mjpeg", "-i", uuidpath, "-f", "s32be", "-ac", "2", "-ar", "44100", "-i", "pipe:0", "-f", "matroska", "-codec", "copy", "pipe:1")
	} else {
		ffmpeg = exec.Command("ffmpeg", "-f", "mjpeg", "-i", uuidpath, "-f", "matroska", "-codec", "copy", "pipe:1")
	}
	ffmpegstdout, err := ffmpeg.StdoutPipe()
	if err != nil {
		log.Fatalf("Unable to setup pipes for ffmpeg (stdout)")
	}
	ffmpeg.Stderr = os.Stderr

	audiofile, err := ffmpeg.StdinPipe()

	go DumpChanToFile(audioin, audiofile)

	ffmpeg.Start()

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

