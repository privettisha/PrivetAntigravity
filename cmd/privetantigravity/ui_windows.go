//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var user32 = windows.NewLazySystemDLL("user32.dll")
var gdi32 = windows.NewLazySystemDLL("gdi32.dll")
var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var createWindow = user32.NewProc("CreateWindowExW")
var sendMessage = user32.NewProc("SendMessageW")
var setText = user32.NewProc("SetWindowTextW")
var mainHWND, logHWND, statusHWND, pathHWND, checkHWND uintptr
var buttons []uintptr
var busy atomic.Bool
var queue = make(chan string, 256)
var doneQueue = make(chan string, 1)
var font, headingFont, smallFont, mediumFont, whiteBrush, backgroundBrush uintptr

const updateMsg = 0x8001
const doneMsg = 0x8002

func w(s string) *uint16      { p, _ := windows.UTF16PtrFromString(s); return p }
func set(h uintptr, s string) { setText.Call(h, uintptr(unsafe.Pointer(w(s)))) }
func get(h uintptr) string {
	n, _, _ := user32.NewProc("GetWindowTextLengthW").Call(h)
	b := make([]uint16, n+1)
	user32.NewProc("GetWindowTextW").Call(h, uintptr(unsafe.Pointer(&b[0])), n+1)
	return windows.UTF16ToString(b)
}
func postLog(s string) { queue <- s; user32.NewProc("PostMessageW").Call(mainHWND, updateMsg, 0, 0) }
func appendLog(s string) {
	sendMessage.Call(logHWND, 0xb1, ^uintptr(0), ^uintptr(0))
	sendMessage.Call(logHWND, 0xc2, 0, uintptr(unsafe.Pointer(w(s+"\r\n"))))
}
func status(s string) { set(statusHWND, s) }
func job(label string, fn func() string) {
	if !busy.CompareAndSwap(false, true) {
		return
	}
	status(label)
	for _, b := range buttons {
		user32.NewProc("EnableWindow").Call(b, 0)
	}
	user32.NewProc("EnableWindow").Call(pathHWND, 0)
	user32.NewProc("EnableWindow").Call(checkHWND, 0)
	go func() { s := fn(); doneQueue <- s; user32.NewProc("PostMessageW").Call(mainHWND, doneMsg, 0, 0) }()
}
func message(s string) {
	user32.NewProc("MessageBoxW").Call(mainHWND, uintptr(unsafe.Pointer(w(s))), uintptr(unsafe.Pointer(w("PrivetAntigravity"))), 0x40)
}
func chooseFile() {
	type ofn struct {
		Size                      uint32
		Owner, Instance           uintptr
		Filter, CustomFilter      *uint16
		MaxCustom, FilterIndex    uint32
		File                      *uint16
		MaxFile                   uint32
		FileTitle                 *uint16
		MaxFileTitle              uint32
		InitialDir, Title         *uint16
		Flags                     uint32
		FileOffset, FileExtension uint16
		DefaultExt                *uint16
		CustomData                uintptr
		Hook, Template            uintptr
		Reserved                  uintptr
		Reserved2, FlagsEx        uint32
	}
	buf := make([]uint16, 32768)
	// UTF16FromString rejects interior NUL; construct the dialog filter explicitly.
	f := []uint16{}
	for _, r := range "Antigravity (*.exe)\x00*.exe\x00Все файлы\x00*.*\x00\x00" {
		f = append(f, uint16(r))
	}
	o := ofn{Owner: mainHWND, Filter: &f[0], FilterIndex: 1, File: &buf[0], MaxFile: uint32(len(buf)), Title: w("Выберите Antigravity.exe или agy.exe"), Flags: 0x1000 | 0x80000 | 8}
	o.Size = uint32(unsafe.Sizeof(o))
	r, _, _ := windows.NewLazySystemDLL("comdlg32.dll").NewProc("GetOpenFileNameW").Call(uintptr(unsafe.Pointer(&o)))
	if r != 0 {
		set(pathHWND, filepath.Dir(windows.UTF16ToString(buf)))
	}
}
func wndProc(hwnd uintptr, msg uint32, wp, lp uintptr) uintptr {
	switch msg {
	case 0x10:
		if busy.Load() {
			message("Дождитесь завершения операции.")
			return 0
		}
		user32.NewProc("DestroyWindow").Call(hwnd)
		return 0
	case 2:
		user32.NewProc("PostQuitMessage").Call(0)
		return 0
	case 0x138, 0x133:
		gdi32.NewProc("SetTextColor").Call(wp, 0x252a20)
		gdi32.NewProc("SetBkMode").Call(wp, 2)
		if lp == logHWND || lp == pathHWND {
			gdi32.NewProc("SetBkColor").Call(wp, 0xffffff)
			return whiteBrush
		}
		gdi32.NewProc("SetBkColor").Call(wp, 0xf4f6f3)
		return backgroundBrush
	case 0x111:
		id := wp & 0xffff
		switch id {
		case 101:
			p := cleanRoot(get(pathHWND))
			watch, _, _ := sendMessage.Call(checkHWND, 0xf0, 0, 0)
			job("Применяем патч…", func() string {
				c := readConfig()
				c.Watch = watch == 1
				if p != "" {
					st, e := os.Stat(p)
					if e != nil || !st.IsDir() {
						return "Папка не найдена. Выберите Antigravity.exe."
					}
					c.Roots = []string{p}
				}
				if e := disableService(); e != nil {
					postLog(e.Error())
					return "Не удалось подготовить сетевые настройки"
				}
				if e := saveConfig(c); e != nil {
					postLog(e.Error())
					return "Не удалось сохранить настройки"
				}
				n, b := patchAll(c, postLog)
				if n == 0 {
					return "Совместимые файлы не найдены. Проверьте папку."
				}
				if e := installService(); e != nil {
					postLog(e.Error())
					return "Патч записан, служба требует внимания"
				}
				if b > 0 {
					return "Включено частично. Подробности в журнале."
				}
				return "Патч и служба включены. Проверьте ответ модели."
			})
		case 102:
			job("Проверяем соединение…", func() string {
				diagnostic(postLog)
				return "Проверка завершена. Результат в журнале."
			})
		case 103:
			job("Откатываем изменения…", func() string {
				if e := disableService(); e != nil {
					postLog(e.Error())
					return "Не удалось выключить сетевые настройки"
				}
				errs := manager().RestoreAll()
				for _, e := range errs {
					postLog(e.Error())
				}
				if len(errs) > 0 {
					return "Служба выключена. Часть файлов требует внимания."
				}
				postLog("Служба удалена, DNS-правила сняты, оригиналы восстановлены.")
				return "Откат завершён. Резервные копии сохранены."
			})
		case 104:
			if e := launchClient(); e != nil {
				message(e.Error())
			}
		case 105:
			chooseFile()
		case 106:
			message(guide)
		case 107:
			p := dataDir()
			windows.ShellExecute(0, w("open"), w(p), nil, nil, 1)
		}
		return 0
	case updateMsg:
		for {
			select {
			case s := <-queue:
				appendLog(s)
			default:
				return 0
			}
		}
	case doneMsg:
		status(<-doneQueue)
		busy.Store(false)
		for _, b := range buttons {
			user32.NewProc("EnableWindow").Call(b, 1)
		}
		user32.NewProc("EnableWindow").Call(pathHWND, 1)
		user32.NewProc("EnableWindow").Call(checkHWND, 1)
		return 0
	}
	r, _, _ := user32.NewProc("DefWindowProcW").Call(hwnd, uintptr(msg), wp, lp)
	return r
}
func control(class, text string, style uint32, x, y, width, height, id int, f uintptr) uintptr {
	h, _, _ := createWindow.Call(0, uintptr(unsafe.Pointer(w(class))), uintptr(unsafe.Pointer(w(text))), uintptr(style|0x50000000), uintptr(x), uintptr(y), uintptr(width), uintptr(height), mainHWND, uintptr(id), 0, 0)
	sendMessage.Call(h, 0x30, f, 1)
	return h
}
func makeFont(height, weight int) uintptr {
	h, _, _ := gdi32.NewProc("CreateFontW").Call(uintptr(int64(-height)), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(w("Segoe UI"))))
	return h
}
func runUI() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mutex, e := windows.CreateMutex(nil, false, w("Local\\PrivetAntigravity-UI"))
	if e == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(mutex)
		return
	}
	if e == nil {
		defer windows.CloseHandle(mutex)
	}
	type wc struct {
		Size, Style                        uint32
		Proc                               uintptr
		ClsExtra, WndExtra                 int32
		Instance, Icon, Cursor, Background uintptr
		Menu, Class                        *uint16
		SmallIcon                          uintptr
	}
	instance, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	cursor, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512)
	icon, _, _ := user32.NewProc("LoadIconW").Call(instance, uintptr(unsafe.Pointer(w("APPICON"))))
	whiteBrush, _, _ = gdi32.NewProc("CreateSolidBrush").Call(0xffffff)
	backgroundBrush, _, _ = gdi32.NewProc("CreateSolidBrush").Call(0xf4f6f3)
	class := w("PrivetAntigravityWindow")
	c := wc{Proc: syscall.NewCallback(wndProc), Instance: instance, Icon: icon, SmallIcon: icon, Cursor: cursor, Background: backgroundBrush, Class: class}
	c.Size = uint32(unsafe.Sizeof(c))
	if r, _, _ := user32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&c))); r == 0 {
		return
	}
	mainHWND, _, _ = createWindow.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(w("PrivetAntigravity"))), 0xca0000|0x10000000, 0x80000000, 0x80000000, 820, 720, 0, 0, instance, 0)
	font = makeFont(17, 400)
	smallFont = makeFont(14, 400)
	headingFont = makeFont(30, 650)
	mediumFont = makeFont(20, 600)
	control("STATIC", "PrivetAntigravity", 0, 28, 24, 570, 42, 0, headingFont)
	control("STATIC", "Для Windows 10/11 · "+version, 0, 28, 70, 730, 23, 0, smallFont)
	statusHWND = control("STATIC", "Готов к настройке", 0, 28, 111, 740, 30, 0, mediumFont)
	control("STATIC", "Сохраните работу и полностью закройте Antigravity перед изменением файлов.", 0, 28, 147, 744, 24, 0, smallFont)
	control("STATIC", "Папка Antigravity · пусто — найти автоматически", 0, 28, 185, 740, 24, 0, font)
	pathHWND = control("EDIT", "", 0x00800000|0x80|0x10000, 28, 214, 600, 31, 0, font)
	cfg := readConfig()
	if len(cfg.Roots) > 0 {
		set(pathHWND, cfg.Roots[0])
	}
	browse := control("BUTTON", "Выбрать…", 0x10000, 640, 213, 134, 33, 105, font)
	logHWND = control("EDIT", "", 0x00200000|0x800|0x4|0x40|0x80|0x00800000|0x10000, 28, 265, 746, 235, 0, smallFont)
	sendMessage.Call(logHWND, 0xc5, 180000, 0)
	enable := control("BUTTON", "Включить", 0x10000|1, 28, 520, 238, 46, 101, mediumFont)
	check := control("BUTTON", "Проверить", 0x10000, 282, 520, 238, 46, 102, font)
	restore := control("BUTTON", "Откатить", 0x10000, 536, 520, 238, 46, 103, font)
	checkHWND = control("BUTTON", "Повторять патч после обновлений Antigravity", 0x10000|3, 28, 579, 570, 29, 108, font)
	v := uintptr(0)
	if cfg.Watch {
		v = 1
	}
	sendMessage.Call(checkHWND, 0xf1, v, 0)
	launch := control("BUTTON", "Запустить Antigravity", 0x10000, 28, 624, 260, 34, 104, font)
	help := control("BUTTON", "Инструкция", 0x10000, 302, 624, 225, 34, 106, font)
	logs := control("BUTTON", "Файлы и журнал", 0x10000, 541, 624, 233, 34, 107, font)
	buttons = []uintptr{browse, enable, check, restore, launch, help, logs}
	appendLog("Без ключей и регистрации. Перед записью создаётся резервная копия.")
	appendLog("Нажмите «Включить». Затем запустите Antigravity и отправьте сообщение модели.")
	appendLog("Проверка сети показывает доступность TLS, результат модели проверяется в самом Antigravity.")
	if p := findClient(); p != "" {
		appendLog("Найден клиент: " + p)
	} else {
		appendLog("Установка пока не найдена. Укажите папку кнопкой «Выбрать…».")
	}
	type point struct{ X, Y int32 }
	type msg struct {
		H       uintptr
		M       uint32
		W, L    uintptr
		Time    uint32
		P       point
		Private uint32
	}
	var m msg
	for {
		r, _, _ := user32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		handled, _, _ := user32.NewProc("IsDialogMessageW").Call(mainHWND, uintptr(unsafe.Pointer(&m)))
		if handled == 0 {
			user32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&m)))
			user32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&m)))
		}
	}
	for _, h := range []uintptr{font, smallFont, headingFont, mediumFont, whiteBrush, backgroundBrush} {
		gdi32.NewProc("DeleteObject").Call(h)
	}
}
