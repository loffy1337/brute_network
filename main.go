package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loffy1337/brute_network/auth"
)

/*
─╔╗──╔══╗╔══╗╔══╗╔╗╔╗───╔╗╔══╗╔══╗╔══╗─
─║║──║╔╗║║╔═╝║╔═╝║║║║──╔╝║╚═╗║╚═╗║╚═╗║─
─║║──║║║║║╚═╗║╚═╗║╚╝║──╚╗║╔═╝║╔═╝║──║║─
─║║──║║║║║╔═╝║╔═╝╚═╗║───║║╚═╗║╚═╗║──║║─
─║╚═╗║╚╝║║║──║║───╔╝║───║║╔═╝║╔═╝║──║║─
─╚══╝╚══╝╚╝──╚╝───╚═╝───╚╝╚══╝╚══╝──╚╝─
*/

// Функция для логирования критических ошибок
func FatalError(errorMessage string) {
	fmt.Printf("[!] ERROR: %s\n", errorMessage)
	os.Exit(1)
}

// Функция для подсчета кол-ва слов в словаре
func CountLines(dictionaryPath string) (uint64, error) {
	file, err := os.Open(dictionaryPath)
	if err != nil {
		return 0, fmt.Errorf("(CountLines) %w", err)
	}
	defer file.Close()
	var counter uint64
	var scanner *bufio.Scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		counter += 1
	}
	return counter, scanner.Err()
}

// Функция для обработки дополнительных попыток при сетевых ошибках
func TryPassword(authenticator auth.Authenticator, login string, password string, timeout time.Duration) bool {
	for i := 0; i < 3; i++ {
		ok, err := authenticator.TryAuth(login, password, timeout)
		if ok {
			return true
		}
		if err == nil {
			return false
		}
	}
	return false
}

func main() {
	var ip, protocol, login, dictionary string
	var port, threads int
	var timeout, delay time.Duration
	var done uint64
	var wg sync.WaitGroup
	// Создание флагов
	flag.StringVar(&ip, "ip", "", "target IP-address")
	flag.IntVar(&port, "port", 0, "target port (0-65535)")
	flag.StringVar(&protocol, "protocol", "", "ssh/ftp/telnet/mysql/postgresql/mssql")
	flag.IntVar(&threads, "threads", 5, "1/2/3/.../8 threads count")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "network timeout")
	flag.DurationVar(&delay, "delay", 3, "sleep time after 1% of progress")
	flag.StringVar(&login, "login", "", "login")
	flag.StringVar(&dictionary, "dictionary", "", "path to passwords dictionary")
	flag.Parse()
	// Валидация полученных данных
	if ip == "" || protocol == "" || login == "" || dictionary == "" {
		flag.Usage()
		return
	}
	if port < 1 || port > 65535 {
		FatalError("port must be 1-65535")
	}
	if threads < 1 || threads > 8 {
		FatalError("threads must be 1-8")
	}
	info, err := os.Stat(dictionary)
	if os.IsNotExist(err) {
		FatalError("dictionary file not exist")
	}
	if info.IsDir() {
		FatalError("dictionary need to be a file, directory given")
	}
	// Подсчет кол-ва строк в словаре
	lineCount, err := CountLines(dictionary)
	if err != nil {
		FatalError(err.Error())
	}
	if lineCount < 1 {
		FatalError("dictionary is empty")
	}
	// Получение переборщика
	authenticator, err := auth.NewAuthenticator(protocol, ip, port)
	if err != nil {
		FatalError(err.Error())
	}
	// Создание каналов для перебора и сигнала об успехе
	var passwordChan chan string = make(chan string, threads*2)
	var foundChan chan string = make(chan string)
	// Запуск потока переборов
	for thread := 0; thread < threads; thread++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range passwordChan {
				var success bool = TryPassword(authenticator, login, password, timeout)
				var progress uint64 = atomic.AddUint64(&done, 1)
				fmt.Printf("[-] INFO: login: %s | password: %s | progress %.2f%%\n", login, password, float64(progress)/float64(lineCount)*100)
				if success {
					foundChan <- fmt.Sprintf("%s:%s", login, password)
					return
				}
				if delay > 0 && progress%uint64(lineCount/100) == 0 {
					time.Sleep(delay)
				}
			}
		}()
	}
	// Поток раздающий пароли потокам перебора
	go func() {
		file, _ := os.Open(dictionary)
		defer file.Close()
		var scanner *bufio.Scanner = bufio.NewScanner(file)
		for scanner.Scan() {
			passwordChan <- scanner.Text()
		}
		close(passwordChan)
	}()

	go func() {
		wg.Wait()
		close(foundChan)
	}()

	if result, ok := <-foundChan; ok {
		fmt.Printf("[+] FOUND: %s\n", result)
	} else {
		fmt.Println("[+] NOT FOUND")
	}
}
