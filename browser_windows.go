//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	shell32DLL        = syscall.NewLazyDLL("shell32.dll")
	shellExecuteWProc = shell32DLL.NewProc("ShellExecuteW")
	ntdllDLL          = syscall.NewLazyDLL("ntdll.dll")
	wineVersionProc   = ntdllDLL.NewProc("wine_get_version")
	user32DLL         = syscall.NewLazyDLL("user32.dll")
	messageBoxWProc   = user32DLL.NewProc("MessageBoxW")
)

func runningUnderWine() bool {
	return wineVersionProc.Find() == nil
}

func shellExecuteURL(url string) error {
	verb, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	target, err := syscall.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	result, _, callErr := shellExecuteWProc.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(target)),
		0,
		0,
		1,
	)
	if result > 32 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return fmt.Errorf("ShellExecuteW returned error code %d", result)
}

func openBrowser(url string) error {
	if runningUnderWine() {
		if err := exec.Command("winebrowser.exe", url).Start(); err == nil {
			return nil
		}
	}
	if err := shellExecuteURL(url); err == nil {
		return nil
	}
	if err := exec.Command("cmd.exe", "/c", "start", "", url).Start(); err == nil {
		return nil
	}
	return fmt.Errorf("no working browser launcher was found; open %s manually", url)
}

func showStartupError(message string) {
	text, textErr := syscall.UTF16PtrFromString(
		"Lanrunner could not start.\n\n" + message,
	)
	title, titleErr := syscall.UTF16PtrFromString("Lanrunner startup error")
	if textErr != nil || titleErr != nil {
		return
	}
	_, _, _ = messageBoxWProc.Call(
		0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(title)),
		0x00000010,
	)
}
