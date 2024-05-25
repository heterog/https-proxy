package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"strings"
	"syscall"
)

func main() {
	var pemPath, keyPath, proto, listen, users string
	var uid, gid int
	flag.StringVar(&pemPath, "pem", "server.pem", "path to pem file")
	flag.StringVar(&keyPath, "key", "server.key", "path to key file")
	flag.StringVar(&proto, "proto", "http", "Proxy protocol (http or https)")
	flag.StringVar(&listen, "listen", ":8080", "listen address, default :8080")
	flag.StringVar(&users, "users", "", "user:password list")
	flag.IntVar(&uid, "uid", -1, "run as user id")
	flag.IntVar(&gid, "gid", -1, "run as group")
	flag.Parse()
	if proto != "http" && proto != "https" {
		log.Fatal("Protocol must be either http or https")
	}

	var userList []User
	for _, up := range strings.Split(users, ";") {
		if ms := strings.Split(up, ":"); len(ms) == 2 && len(ms[0]) > 0 {
			userList = append(userList, User{ms[0], ms[1]})
		}
	}

	server := &http.Server{
		Addr: listen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if len(userList) > 0 && !basicAuth(w, r, userList) {
				return
			}

			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// TLSNextProto not-nil to disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if proto == "http" {
		log.Fatal(server.ListenAndServe())
	} else {
		// https://github.com/golang/go/blob/377646589d5fb0224014683e0d1f1db35e60c3ac/src/net/http/server.go#L3342
		var err error
		tlsConfig := tls.Config{}
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(pemPath, keyPath)
		if err != nil {
			log.Fatal("Failed to load x509 key, " + err.Error())
		}

		// Drop root privileges, and switch to nobody:nogroup (hardcoded as 65534:65534)
		if gid > 0 {
			err = syscall.Setgroups([]int{})
			if err != nil {
				log.Fatal("Failed to unset groups, " + err.Error())
			}

			err = syscall.Setgid(65534)
			if err != nil {
				log.Fatal("Failed to set new group, " + err.Error())
			}
		}

		if uid > 0 {
			err = syscall.Setuid(65534)
			if err != nil {
				log.Fatal("Failed to set new user, " + err.Error())
			}
		}

		// Bring-it-up
		server.TLSConfig = &tlsConfig
		log.Fatal(server.ListenAndServeTLS("", ""))
	}
}
