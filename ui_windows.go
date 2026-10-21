//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/realCreeper938/launcher-patcher/internal/patcher"
)

const (
	idleText = "点击窗口任意处选择启动器文件"

	wmCreate       = 0x0001
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmPaint        = 0x000F
	wmEraseBkgnd   = 0x0014
	wmKeyDown      = 0x0100
	wmLButtonUp    = 0x0202
	wmDropFiles    = 0x0233
	wmDPIChanged   = 0x02E0
	wmAppDone      = 0x8001
	wmAppProgress  = 0x8002
	vkEscape       = 0x1B
	dtCenter       = 0x0001
	dtWordBreak    = 0x0010
	dtSingleLine   = 0x0020
	dtEndEllipsis  = 0x8000
	dtNoPrefix     = 0x2000
	mbOK           = 0x0000
	mbIconError    = 0x0010
	mbIconInfo     = 0x0040
	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsClipChildren = 0x02000000
	wsExAppWindow  = 0x00040000
	swShow         = 5
	swpNoZOrder    = 0x0004
	swpNoActivate  = 0x0010
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	comdlg32 = syscall.NewLazyDLL("comdlg32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW       = user32.NewProc("RegisterClassExW")
	procCreateWindowExW        = user32.NewProc("CreateWindowExW")
	procDefWindowProcW         = user32.NewProc("DefWindowProcW")
	procShowWindow             = user32.NewProc("ShowWindow")
	procUpdateWindow           = user32.NewProc("UpdateWindow")
	procGetMessageW            = user32.NewProc("GetMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessageW       = user32.NewProc("DispatchMessageW")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procPostMessageW           = user32.NewProc("PostMessageW")
	procDestroyWindow          = user32.NewProc("DestroyWindow")
	procInvalidateRect         = user32.NewProc("InvalidateRect")
	procGetClientRect          = user32.NewProc("GetClientRect")
	procBeginPaint             = user32.NewProc("BeginPaint")
	procEndPaint               = user32.NewProc("EndPaint")
	procFillRect               = user32.NewProc("FillRect")
	procDrawTextW              = user32.NewProc("DrawTextW")
	procLoadCursorW            = user32.NewProc("LoadCursorW")
	procLoadIconW              = user32.NewProc("LoadIconW")
	procSetWindowPos           = user32.NewProc("SetWindowPos")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procAdjustWindowRectEx     = user32.NewProc("AdjustWindowRectEx")
	procGetDpiForWindow        = user32.NewProc("GetDpiForWindow")
	procGetDpiForSystem        = user32.NewProc("GetDpiForSystem")
	procSetProcessDPIAware     = user32.NewProc("SetProcessDPIAware")
	procSetDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
	procDragAcceptFiles        = shell32.NewProc("DragAcceptFiles")
	procDragQueryFileW         = shell32.NewProc("DragQueryFileW")
	procDragFinish             = shell32.NewProc("DragFinish")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procCreateSolidBrush       = gdi32.NewProc("CreateSolidBrush")
	procSetBkMode              = gdi32.NewProc("SetBkMode")
	procSetTextColor           = gdi32.NewProc("SetTextColor")
	procCreateFontW            = gdi32.NewProc("CreateFontW")
	procCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	procCreateBitmap           = gdi32.NewProc("CreateBitmap")
	procCreateIconIndirect     = user32.NewProc("CreateIconIndirect")
	procDrawIconEx             = user32.NewProc("DrawIconEx")
	procGetOpenFileNameW       = comdlg32.NewProc("GetOpenFileNameW")
	procMessageBoxW            = user32.NewProc("MessageBoxW")

	wndProcCallback uintptr
	mainWindow      uintptr

	uiMu       sync.Mutex
	uiStatus   = idleText
	uiError    bool
	uiBusy     bool
	uiProgress int
	uiLog      []string
	uiPending  *patchOutcome
)

type point struct {
	x int32
	y int32
}

type rect struct {
	left   int32
	top    int32
	right  int32
	bottom int32
}

type paintStruct struct {
	hdc         uintptr
	fErase      int32
	rcPaint     rect
	fRestore    int32
	fIncUpdate  int32
	rgbReserved [32]byte
}

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type winMessage struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

type patchOutcome struct {
	summary string
	failed  bool
	outputs []string
}

type openFileName struct {
	lStructSize       uint32
	_                 uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	_                 uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	_                 uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

func runUI() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	enableDPIAwareness()

	instance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("LauncherPatcherWindow")
	windowTitle, _ := syscall.UTF16PtrFromString("启动器补丁器")
	if className == nil || windowTitle == nil {
		logError(fmt.Errorf("无法创建窗口文本"))
		return
	}

	wndProcCallback = syscall.NewCallback(windowProc)
	class := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   wndProcCallback,
		hInstance:     instance,
		hIcon:         loadIcon(32512),
		hCursor:       loadCursor(32512),
		lpszClassName: className,
		hIconSm:       loadIcon(32512),
	}
	if result, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&class))); result == 0 {
		_ = err
	}

	style := uint32(wsOverlapped | wsCaption | wsSysMenu | wsClipChildren)
	exStyle := uint32(wsExAppWindow)
	scale := float64(systemDPI()) / 96.0
	clientWidth := int32(520 * scale)
	clientHeight := int32(380 * scale)
	frame := rect{right: clientWidth, bottom: clientHeight}
	procAdjustWindowRectEx.Call(
		uintptr(unsafe.Pointer(&frame)),
		uintptr(style),
		0,
		uintptr(exStyle),
	)
	windowWidth := frame.right - frame.left
	windowHeight := frame.bottom - frame.top
	screenWidth, _, _ := procGetSystemMetrics.Call(0)
	screenHeight, _, _ := procGetSystemMetrics.Call(1)
	x := (int32(screenWidth) - windowWidth) / 2
	y := (int32(screenHeight) - windowHeight) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	hwnd, _, err := procCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		uintptr(style),
		uintptr(uint32(x)),
		uintptr(uint32(y)),
		uintptr(uint32(windowWidth)),
		uintptr(uint32(windowHeight)),
		0,
		0,
		instance,
		0,
	)
	if hwnd == 0 {
		logError(fmt.Errorf("创建窗口失败: %v", err))
		return
	}
	mainWindow = hwnd

	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	procDragAcceptFiles.Call(hwnd, 1)

	var message winMessage
	for {
		result, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&message)))
	}
}

func enableDPIAwareness() {
	if err := procSetDpiAwarenessContext.Find(); err == nil {
		if result, _, _ := procSetDpiAwarenessContext.Call(^uintptr(3)); result != 0 {
			return
		}
	}
	if err := procSetProcessDPIAware.Find(); err == nil {
		procSetProcessDPIAware.Call()
	}
}

func systemDPI() int {
	if err := procGetDpiForSystem.Find(); err == nil {
		if dpi, _, _ := procGetDpiForSystem.Call(); dpi >= 72 && dpi <= 768 {
			return int(dpi)
		}
	}
	return 96
}

func windowDPI(hwnd uintptr) int {
	if err := procGetDpiForWindow.Find(); err == nil {
		if dpi, _, _ := procGetDpiForWindow.Call(hwnd); dpi >= 72 && dpi <= 768 {
			return int(dpi)
		}
	}
	return 96
}

func loadCursor(id uintptr) uintptr {
	value, _, _ := procLoadCursorW.Call(0, id)
	return value
}

func loadIcon(id uintptr) uintptr {
	value, _, _ := procLoadIconW.Call(0, id)
	return value
}

func windowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmCreate:
		procDragAcceptFiles.Call(hwnd, 1)
		return 0
	case wmLButtonUp:
		if !isBusy() {
			chooseAndPatch(hwnd)
		}
		return 0
	case wmDropFiles:
		handleDrop(hwnd, wParam)
		return 0
	case wmPaint:
		paintWindow(hwnd)
		return 0
	case wmEraseBkgnd:
		return 1
	case wmKeyDown:
		if wParam == vkEscape && !isBusy() {
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case wmClose:
		if !isBusy() {
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case wmAppProgress:
		procInvalidateRect.Call(hwnd, 0, 0)
		procUpdateWindow.Call(hwnd)
		return 0
	case wmAppDone:
		finishProcessing(hwnd)
		return 0
	case wmDPIChanged:
		resizeForDPI(hwnd, lParam)
		procInvalidateRect.Call(hwnd, 0, 1)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	default:
		result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
		return result
	}
}

func handleDrop(hwnd, hDrop uintptr) {
	if isBusy() {
		procDragFinish.Call(hDrop)
		return
	}

	count, _, _ := procDragQueryFileW.Call(hDrop, 0xffffffff, 0, 0)
	paths := make([]string, 0, int(count))
	for i := uintptr(0); i < count; i++ {
		length, _, _ := procDragQueryFileW.Call(hDrop, i, 0, 0)
		if length == 0 {
			continue
		}
		buffer := make([]uint16, int(length)+1)
		procDragQueryFileW.Call(
			hDrop,
			i,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
		)
		paths = append(paths, syscall.UTF16ToString(buffer))
	}
	procDragFinish.Call(hDrop)

	if len(paths) == 0 {
		return
	}
	startPatch(hwnd, paths)
}

func chooseAndPatch(hwnd uintptr) {
	filter := make([]uint16, 0, 64)
	for _, part := range []string{"启动器文件", "*.exe;*.jar", "所有文件", "*.*"} {
		value, err := syscall.UTF16FromString(part)
		if err != nil {
			return
		}
		filter = append(filter, value...)
	}
	filter = append(filter, 0)

	buffer := make([]uint16, 1024)
	title, _ := syscall.UTF16PtrFromString("选择启动器文件")
	open := openFileName{
		lStructSize:  uint32(unsafe.Sizeof(openFileName{})),
		hwndOwner:    hwnd,
		lpstrFilter:  &filter[0],
		nFilterIndex: 1,
		lpstrFile:    &buffer[0],
		nMaxFile:     uint32(len(buffer)),
		lpstrTitle:   title,
		flags:        0x00001000 | 0x00000800 | 0x00080000 | 0x00000008 | 0x00000004,
	}
	result, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&open)))
	if result == 0 {
		return
	}
	length := 0
	for length < len(buffer) && buffer[length] != 0 {
		length++
	}
	if length == 0 {
		return
	}
	startPatch(hwnd, []string{syscall.UTF16ToString(buffer[:length])})
}

func startPatch(hwnd uintptr, paths []string) {
	uiMu.Lock()
	if uiBusy {
		uiMu.Unlock()
		return
	}
	uiBusy = true
	uiError = false
	uiProgress = 0
	uiLog = nil
	uiStatus = "正在修补，请稍候…"
	uiMu.Unlock()

	procInvalidateRect.Call(hwnd, 0, 0)
	procUpdateWindow.Call(hwnd)

	go func() {
		started := time.Now()
		outcome := runPatches(hwnd, paths)
		if elapsed := time.Since(started); elapsed < 600*time.Millisecond {
			time.Sleep(600*time.Millisecond - elapsed)
		}
		uiMu.Lock()
		uiPending = &outcome
		uiMu.Unlock()
		procPostMessageW.Call(hwnd, wmAppDone, 0, 0)
	}()
}

func reportProgress(hwnd uintptr, progress patcher.Progress) {
	uiMu.Lock()
	if progress.Percent >= 0 {
		uiProgress = progress.Percent
	}
	if progress.Line != "" {
		uiLog = append(uiLog, progress.Line)
		if len(uiLog) > 200 {
			uiLog = uiLog[len(uiLog)-200:]
		}
	}
	uiMu.Unlock()
	procPostMessageW.Call(hwnd, wmAppProgress, 0, 0)
}

func runPatches(hwnd uintptr, paths []string) patchOutcome {
	logLines := make([]string, 0, len(paths))
	var outputs []string
	var notes []string
	var failures []string

	total := len(paths)
	if total == 0 {
		total = 1
	}
	for index, path := range paths {
		base := index * 100 / total
		endPercent := (index + 1) * 100 / total
		span := endPercent - base
		reporter := func(progress patcher.Progress) {
			reportProgress(hwnd, patcher.Progress{
				Percent: base + progress.Percent*span/100,
				Line:    progress.Line,
			})
		}
		result, err := patcher.PatchFileWithReporter(path, reporter)
		logLines = append(logLines, formatLogLine(path, result, err))
		if err != nil {
			failures = append(failures, filepath.Base(path)+": "+err.Error())
			continue
		}
		if result.Changed {
			outputs = append(outputs, result.Output)
		} else if result.Note != "" {
			notes = append(notes, result.Note)
		}
	}
	writeRunLog(logLines)

	if len(failures) > 0 {
		summary := "修补失败：" + truncateRunes(failures[0], 150)
		if len(failures) > 1 {
			summary = fmt.Sprintf("修补失败（共 %d 个文件）：%s", len(failures), truncateRunes(failures[0], 120))
		}
		summary += "\n\n详细日志：" + lastLogPath()
		return patchOutcome{summary: summary, failed: true}
	}

	if len(outputs) > 0 {
		summary := "修补完成，已生成 " + filepath.Base(outputs[0])
		if len(outputs) > 1 {
			summary = fmt.Sprintf("修补完成，已生成 %d 个文件", len(outputs))
		}
		return patchOutcome{summary: summary, outputs: outputs}
	}

	summary := "无需修补：未检测到区域限制。"
	if len(notes) == 1 {
		summary = notes[0]
	}
	return patchOutcome{summary: summary}
}

func finishProcessing(hwnd uintptr) {
	uiMu.Lock()
	outcome := uiPending
	uiPending = nil
	if outcome != nil {
		uiStatus = outcome.summary
		uiError = outcome.failed
		uiBusy = false
		if uiProgress < 100 {
			uiProgress = 100
		}
	}
	uiMu.Unlock()

	procInvalidateRect.Call(hwnd, 0, 0)
	procUpdateWindow.Call(hwnd)

	if outcome == nil {
		return
	}
	if outcome.failed {
		showMessage(hwnd, outcome.summary, "修补失败", mbOK|mbIconError)
		return
	}
	if len(outcome.outputs) > 0 {
		showMessage(hwnd, "修补完成。\n\n输出文件：\n"+strings.Join(outcome.outputs, "\n"), "修补完成", mbOK|mbIconInfo)
		return
	}
	if outcome.summary != "" {
		showMessage(hwnd, outcome.summary, "提示", mbOK|mbIconInfo)
	}
}

func showMessage(hwnd uintptr, text, caption string, flags uint32) {
	t, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	c, err := syscall.UTF16PtrFromString(caption)
	if err != nil {
		return
	}
	procMessageBoxW.Call(hwnd, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), uintptr(flags))
}

func isBusy() bool {
	uiMu.Lock()
	defer uiMu.Unlock()
	return uiBusy
}

func resizeForDPI(hwnd, lParam uintptr) {
	if lParam == 0 {
		return
	}
	suggested := (*rect)(unsafe.Pointer(lParam))
	procSetWindowPos.Call(
		hwnd,
		0,
		uintptr(uint32(suggested.left)),
		uintptr(uint32(suggested.top)),
		uintptr(uint32(suggested.right-suggested.left)),
		uintptr(uint32(suggested.bottom-suggested.top)),
		swpNoZOrder|swpNoActivate,
	)
}

func paintWindow(hwnd uintptr) {
	var paint paintStruct
	hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
	if hdc == 0 {
		return
	}
	defer procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))

	var client rect
	if result, _, _ := procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&client))); result == 0 {
		return
	}

	uiMu.Lock()
	status := uiStatus
	isError := uiError
	busy := uiBusy
	progress := uiProgress
	logLines := append([]string(nil), uiLog...)
	uiMu.Unlock()

	background, _, _ := procCreateSolidBrush.Call(colorRef(246, 247, 249))
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&client)), background)
	procDeleteObject.Call(background)

	scale := float64(windowDPI(hwnd)) / 96.0

	supportRect := rect{
		left:   int32(20 * scale),
		right:  client.right - int32(20*scale),
		top:    int32(14 * scale),
		bottom: int32(36 * scale),
	}
	drawTextLine(hdc, "支持以下启动器", supportRect, -int32(14*scale), colorRef(99, 105, 116), 400, dtCenter|dtWordBreak|dtNoPrefix)

	iconSize := int32(48 * scale)
	iconGap := int32(26 * scale)
	icons := launcherIcons(int(iconSize))
	if len(icons) > 0 {
		totalWidth := int32(len(icons))*iconSize + int32(len(icons)-1)*iconGap
		iconLeft := (client.right - totalWidth) / 2
		iconTop := int32(44 * scale)
		for index, icon := range icons {
			left := iconLeft + int32(index)*(iconSize+iconGap)
			procDrawIconEx.Call(
				hdc,
				uintptr(uint32(left)),
				uintptr(uint32(iconTop)),
				icon,
				uintptr(uint32(iconSize)),
				uintptr(uint32(iconSize)),
				0,
				0,
				0x0003,
			)
		}
	}

	statusRect := rect{
		left:   int32(26 * scale),
		right:  client.right - int32(26*scale),
		top:    int32(108 * scale),
		bottom: int32(164 * scale),
	}
	textColor := colorRef(44, 48, 56)
	if isError {
		textColor = colorRef(180, 35, 24)
	}
	drawTextLine(hdc, status, statusRect, -int32(18*scale), textColor, 400, dtCenter|dtWordBreak|dtNoPrefix)

	if busy || progress > 0 {
		bar := rect{
			left:   int32(36 * scale),
			right:  client.right - int32(36*scale),
			top:    int32(170 * scale),
			bottom: int32(178 * scale),
		}
		drawProgressBar(hdc, bar, progress)
	}

	logRect := rect{
		left:   int32(28 * scale),
		right:  client.right - int32(28*scale),
		top:    int32(192 * scale),
		bottom: client.bottom - int32(34*scale),
	}
	drawLogLines(hdc, logLines, logRect, scale)

	footer := ""
	if busy {
		footer = "正在处理，请稍候"
	} else if len(logLines) > 0 {
		footer = "点击窗口任意处继续修补"
	}
	if footer != "" {
		footerRect := rect{
			left:   int32(20 * scale),
			right:  client.right - int32(20*scale),
			top:    client.bottom - int32(28*scale),
			bottom: client.bottom - int32(10*scale),
		}
		drawTextLine(hdc, footer, footerRect, -int32(11*scale), colorRef(130, 136, 146), 400, dtCenter|dtSingleLine|dtNoPrefix)
	}
}

func drawProgressBar(hdc uintptr, bounds rect, percent int) {
	if bounds.right <= bounds.left || bounds.bottom <= bounds.top {
		return
	}
	track, _, _ := procCreateSolidBrush.Call(colorRef(226, 229, 235))
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&bounds)), track)
	procDeleteObject.Call(track)

	if percent <= 0 {
		return
	}
	if percent > 100 {
		percent = 100
	}
	fillRect := bounds
	fillRect.right = bounds.left + int32(int64(bounds.right-bounds.left)*int64(percent)/100)
	fill, _, _ := procCreateSolidBrush.Call(colorRef(71, 120, 245))
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&fillRect)), fill)
	procDeleteObject.Call(fill)
}

func drawLogLines(hdc uintptr, lines []string, bounds rect, scale float64) {
	if len(lines) == 0 {
		return
	}
	lineHeight := int32(18 * scale)
	if lineHeight <= 0 {
		return
	}
	maxLines := int((bounds.bottom - bounds.top) / lineHeight)
	if maxLines <= 0 {
		return
	}
	start := len(lines) - maxLines
	if start < 0 {
		start = 0
	}
	for index, line := range lines[start:] {
		top := bounds.top + int32(index)*lineHeight
		row := rect{
			left:   bounds.left,
			right:  bounds.right,
			top:    top,
			bottom: top + lineHeight,
		}
		drawTextLine(hdc, line, row, -int32(12*scale), colorRef(102, 108, 118), 400, dtSingleLine|dtEndEllipsis|dtNoPrefix)
	}
}

func drawTextLine(hdc uintptr, value string, bounds rect, fontHeight int32, textColor uintptr, weight uint32, flags uint32) {
	if value == "" {
		return
	}
	face, _ := syscall.UTF16PtrFromString("Microsoft YaHei UI")
	font, _, _ := procCreateFontW.Call(
		uintptr(uint32(fontHeight)),
		0,
		0,
		0,
		uintptr(weight),
		0,
		0,
		0,
		1,
		0,
		0,
		5,
		0,
		uintptr(unsafe.Pointer(face)),
	)
	oldFont := uintptr(0)
	if font != 0 {
		oldFont, _, _ = procSelectObject.Call(hdc, font)
	}
	defer func() {
		if font != 0 {
			procSelectObject.Call(hdc, oldFont)
			procDeleteObject.Call(font)
		}
	}()

	procSetBkMode.Call(hdc, 1)
	procSetTextColor.Call(hdc, textColor)
	text, _ := syscall.UTF16PtrFromString(value)
	if text == nil {
		return
	}
	procDrawTextW.Call(
		hdc,
		uintptr(unsafe.Pointer(text)),
		uintptr(^uint32(0)),
		uintptr(unsafe.Pointer(&bounds)),
		uintptr(flags),
	)
}

func colorRef(red, green, blue uint8) uintptr {
	return uintptr(red) | uintptr(green)<<8 | uintptr(blue)<<16
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}
