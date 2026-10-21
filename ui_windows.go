//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/realCreeper938/launcher-patcher/internal/patcher"
)

const (
	idleText = "将要修补的启动器文件拖到此窗口"

	wmCreate       = 0x0001
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmPaint        = 0x000F
	wmEraseBkgnd   = 0x0014
	wmKeyDown      = 0x0100
	wmTimer        = 0x0113
	wmDropFiles    = 0x0233
	wmDPIChanged   = 0x02E0
	wmAppDone      = 0x8001
	closeTimerID   = 1
	vkEscape       = 0x1B
	dtCenter       = 0x0001
	dtWordBreak    = 0x0010
	dtNoPrefix     = 0x2000
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
	procSetTimer               = user32.NewProc("SetTimer")
	procKillTimer              = user32.NewProc("KillTimer")
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
	procCreatePen              = gdi32.NewProc("CreatePen")
	procGetStockObject         = gdi32.NewProc("GetStockObject")
	procRoundRect              = gdi32.NewProc("RoundRect")
	procPolygon                = gdi32.NewProc("Polygon")
	procSetBkMode              = gdi32.NewProc("SetBkMode")
	procSetTextColor           = gdi32.NewProc("SetTextColor")
	procCreateFontW            = gdi32.NewProc("CreateFontW")
	procCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	procCreateBitmap           = gdi32.NewProc("CreateBitmap")
	procCreateIconIndirect     = user32.NewProc("CreateIconIndirect")
	procDrawIconEx             = user32.NewProc("DrawIconEx")

	wndProcCallback uintptr
	mainWindow      uintptr

	uiMu      sync.Mutex
	uiStatus  = idleText
	uiError   bool
	uiBusy    bool
	uiPending *patchOutcome
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
	summary    string
	failed     bool
	closeDelay uintptr
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
	clientHeight := int32(340 * scale)
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
	case wmDropFiles:
		procKillTimer.Call(hwnd, closeTimerID)
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
	case wmTimer:
		if wParam == closeTimerID {
			procKillTimer.Call(hwnd, closeTimerID)
			if !isBusy() {
				procDestroyWindow.Call(hwnd)
			}
		}
		return 0
	case wmAppDone:
		finishProcessing(hwnd)
		return 0
	case wmDPIChanged:
		resizeForDPI(hwnd, lParam)
		procInvalidateRect.Call(hwnd, 0, 1)
		return 0
	case wmDestroy:
		procKillTimer.Call(hwnd, closeTimerID)
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

	uiMu.Lock()
	if uiBusy {
		uiMu.Unlock()
		return
	}
	uiBusy = true
	uiError = false
	uiStatus = "正在检查并修补，请稍候…"
	uiMu.Unlock()

	procInvalidateRect.Call(hwnd, 0, 1)
	procUpdateWindow.Call(hwnd)

	go func() {
		outcome := runPatches(paths)
		uiMu.Lock()
		uiPending = &outcome
		uiMu.Unlock()
		procPostMessageW.Call(hwnd, wmAppDone, 0, 0)
	}()
}

func runPatches(paths []string) patchOutcome {
	logLines := make([]string, 0, len(paths))
	var outputs []string
	var notes []string
	var failures []string

	for _, path := range paths {
		result, err := patcher.PatchFile(path)
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
		return patchOutcome{summary: summary, closeDelay: 1200}
	}

	summary := "无需修补：未检测到区域限制。"
	if len(notes) == 1 {
		summary = notes[0]
	}
	return patchOutcome{summary: summary, closeDelay: 2000}
}

func finishProcessing(hwnd uintptr) {
	uiMu.Lock()
	outcome := uiPending
	uiPending = nil
	if outcome != nil {
		uiStatus = outcome.summary
		uiError = outcome.failed
		uiBusy = false
	}
	uiMu.Unlock()

	procInvalidateRect.Call(hwnd, 0, 1)
	procUpdateWindow.Call(hwnd)
	if outcome != nil && !outcome.failed && outcome.closeDelay > 0 {
		procSetTimer.Call(hwnd, closeTimerID, outcome.closeDelay, 0)
	}
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
	drawTextLine(hdc, "支持以下启动器", supportRect, -int32(14*scale), colorRef(99, 105, 116), 400)

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

	dropSize := int32(108 * scale)
	dropTop := int32(102 * scale)
	dropLeft := (client.right - dropSize) / 2
	drawDropIcon(hdc, dropLeft, dropTop, dropSize, scale, isError)

	textTop := dropTop + dropSize + int32(14*scale)
	textRect := rect{
		left:   int32(24 * scale),
		top:    textTop,
		right:  client.right - int32(24*scale),
		bottom: client.bottom - int32(14*scale),
	}
	textColor := colorRef(44, 48, 56)
	if isError {
		textColor = colorRef(180, 35, 24)
	}
	drawTextLine(hdc, status, textRect, -int32(19*scale), textColor, 400)
}

func drawTextLine(hdc uintptr, value string, bounds rect, fontHeight int32, textColor uintptr, weight uint32) {
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
		dtCenter|dtWordBreak|dtNoPrefix,
	)
}

func drawDropIcon(hdc uintptr, left, top, size int32, scale float64, isError bool) {
	tileColor := colorRef(71, 120, 245)
	if isError {
		tileColor = colorRef(216, 76, 76)
	}
	tile, _, _ := procCreateSolidBrush.Call(tileColor)
	nullPen, _, _ := procGetStockObject.Call(8)
	oldBrush, _, _ := procSelectObject.Call(hdc, tile)
	oldPen, _, _ := procSelectObject.Call(hdc, nullPen)
	procRoundRect.Call(
		hdc,
		uintptr(uint32(left)),
		uintptr(uint32(top)),
		uintptr(uint32(left+size)),
		uintptr(uint32(top+size)),
		uintptr(uint32(size/4)),
		uintptr(uint32(size/4)),
	)
	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(tile)

	whiteBrush, _, _ := procGetStockObject.Call(0)
	if whiteBrush == 0 {
		return
	}
	oldBrush, _, _ = procSelectObject.Call(hdc, whiteBrush)
	oldPen, _, _ = procSelectObject.Call(hdc, nullPen)

	unit := func(value float64) int32 { return int32(value * scale) }
	cx := left + size/2
	shaftLeft := cx - unit(9)
	shaftRight := cx + unit(9)
	shaftTop := top + unit(21)
	headTop := top + unit(59)
	headLeft := cx - unit(27)
	headRight := cx + unit(27)
	tip := top + unit(87)
	points := []point{
		{x: shaftLeft, y: shaftTop},
		{x: shaftRight, y: shaftTop},
		{x: shaftRight, y: headTop},
		{x: headRight, y: headTop},
		{x: cx, y: tip},
		{x: headLeft, y: headTop},
		{x: shaftLeft, y: headTop},
	}
	procPolygon.Call(hdc, uintptr(unsafe.Pointer(&points[0])), uintptr(len(points)))

	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
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
