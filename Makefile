gen:
	gofumpt -l -w .
	go build  -ldflags '-w -s' -trimpath
all:
	make gen