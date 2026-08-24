package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"glock/internal/watch"
)

func openUeventSocket() (*os.File, error) {
	fd, err := syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_RAW|syscall.SOCK_CLOEXEC,
		syscall.NETLINK_KOBJECT_UEVENT,
	)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: 1,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	return os.NewFile(uintptr(fd), "netlink-uevent"), nil
}

func extractEvent(buf []byte) watch.Event {
	if i := indexBytes(buf, []byte("ACTION@")); i >= 0 {
		buf = buf[i:]
	} else if i := indexBytes(buf, []byte("ACTION=")); i >= 0 {
		buf = buf[i:]
	}
	return watch.ParseUevent(string(buf))
}

func indexBytes(b, sep []byte) int {
	return strings.Index(string(b), string(sep))
}

func main() {
	execCmd := flag.String("exec", "", "команда запуска при подключении айфона")
	cooldown := flag.Duration("cooldown", 90*time.Second, "минимальный интервал между аудитами")
	settle := flag.Duration("settle", 5*time.Second, "пауза после подключения перед запуском")
	testEvent := flag.Bool("test-event", false, "инъектировать фейковое событие iPhone для проверки цепочки")
	flag.Parse()

	if *execCmd == "" {
		log.Fatal("-exec обязателен, например: -exec 'python3 /path/ghost_lock.py audit'")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := openUeventSocket()
	if err != nil {
		log.Fatalf("не удалось открыть uevent-сокет: %v (запускай не в контейнере без netns)", err)
	}
	defer conn.Close()
	log.Printf("glock-watch: слушаю USB-события (cooldown=%s settle=%s)", *cooldown, *settle)

	var lastRun time.Time

	fire := func(reason string) {
		if time.Since(lastRun) < *cooldown {
			log.Printf("пропускаю %q: не прошёл cooldown", reason)
			return
		}
		lastRun = time.Now()
		log.Printf("iPhone подключён (%s) — пауза %s и запуск: %s", reason, *settle, *execCmd)

		time.Sleep(*settle)

		cmd := exec.CommandContext(ctx, "sh", "-c", *execCmd)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
				log.Printf("[audit] %s", line)
			}
		}
		if err != nil {
			log.Printf("[audit] завершился с ошибкой: %v", err)
		} else {
			log.Printf("[audit] готово")
		}
	}

	if *testEvent {
		fire("test-event")
		return
	}

	buf := make([]byte, 8192)
	done := make(chan error, 1)
	go func() {
		for {
			n, err := conn.Read(buf)
			if err != nil {
				done <- err
				return
			}
			ev := extractEvent(buf[:n])
			if watch.IsAppleDeviceAdd(ev) {
				fire(ev["PRODUCT"])
			}
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("glock-watch: остановлен")
	case err := <-done:
		log.Fatalf("сокет закрылся: %v", err)
	}
}
