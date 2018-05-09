all: sancrawler

clean:
	rm sancrawler

sancrawler:
	go build sancrawler.go
