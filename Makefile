test:
	go test -race $(shell go list ./... | grep -v /examples/)
