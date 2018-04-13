#!/bin/bash
export GOPATH=~/vgo
go test -v -run=$1 .