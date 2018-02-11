package sscanner

import (
	"testing"
	"time"

	"github.com/Centny/gwf/util"
)

func TestScanner(t *testing.T) {
	cfg := util.NewFcfg3()
	cfg.InitWithUri2("whitelist.conf", false)
	scanner := NewScanner(true, true)
	scanner.Warner = NewCmdWarner(cfg.Val2("warner", ""))
	scanner.Start(3, 3)
	err := scanner.Scan(cfg)
	if err != nil {
		t.Error(err)
	}
	time.Sleep(5 * time.Second)
}
