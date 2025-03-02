package util

import (
	"log"
	"runtime"
	"time"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
)

// FunctionTracer provides function execution tracing with colored output
func Trace() func() {
	// Get function name through runtime reflection
	pc, _, _, ok := runtime.Caller(1)
	funcName := "unknown"
	if ok {
		funcName = runtime.FuncForPC(pc).Name()
	}
	
	log.Printf("%s▶ TRACE: Function %s started%s", colorGreen, funcName, colorReset)
	start := time.Now()
	
	return func() {
		elapsed := time.Since(start)
		// Use different colors based on execution time
		durationColor := colorGreen
		if elapsed > 100*time.Millisecond {
			durationColor = colorYellow
		}
		if elapsed > 500*time.Millisecond {
			durationColor = colorRed
		}
		
		log.Printf("%s◼ TRACE: Function %s ended %s(took %s%v%s)%s", 
			colorBlue, funcName, colorReset, 
			durationColor, elapsed, colorReset, colorReset)
	}
}