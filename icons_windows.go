//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"image"
	"image/draw"
	"image/png"
	"math"
	"sync"
	"unsafe"
)

//go:embed assets/pcl2.png
var pcl2IconPNG []byte

//go:embed assets/pclce.png
var pclceIconPNG []byte

//go:embed assets/hmcl.png
var hmclIconPNG []byte

var iconSources = [][]byte{pcl2IconPNG, pclceIconPNG, hmclIconPNG}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

type bitmapInfo struct {
	bmiHeader bitmapInfoHeader
	bmiColors [1]uint32
}

type iconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

var (
	iconMu      sync.Mutex
	iconCache   = make(map[int][]uintptr)
	iconDecoded []*image.RGBA
	iconDecode  sync.Once
)

func launcherIcons(size int) []uintptr {
	if size < 8 || size > 256 {
		return nil
	}

	iconMu.Lock()
	defer iconMu.Unlock()
	if cached, ok := iconCache[size]; ok {
		return cached
	}

	iconDecode.Do(func() {
		iconDecoded = make([]*image.RGBA, 0, len(iconSources))
		for _, source := range iconSources {
			img, err := png.Decode(bytes.NewReader(source))
			if err != nil {
				iconDecoded = nil
				return
			}
			bounds := img.Bounds()
			rgba := image.NewRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
			draw.Draw(rgba, rgba.Bounds(), img, bounds.Min, draw.Src)
			iconDecoded = append(iconDecoded, rgba)
		}
	})

	icons := make([]uintptr, 0, len(iconDecoded))
	for _, source := range iconDecoded {
		scaled := scaleIcon(source, size)
		handle := createIconHandle(scaled)
		if handle == 0 {
			continue
		}
		icons = append(icons, handle)
	}
	iconCache[size] = icons
	return icons
}

func scaleIcon(source *image.RGBA, size int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	sw := float64(source.Bounds().Dx())
	sh := float64(source.Bounds().Dy())
	if sw <= 0 || sh <= 0 {
		return dst
	}
	for y := 0; y < size; y++ {
		fy := (float64(y)+0.5)*sh/float64(size) - 0.5
		y0 := int(math.Floor(fy))
		wy := fy - float64(y0)
		if y0 < 0 {
			y0, wy = 0, 0
		}
		y1 := y0 + 1
		if y1 >= int(sh) {
			y1 = int(sh) - 1
		}
		for x := 0; x < size; x++ {
			fx := (float64(x)+0.5)*sw/float64(size) - 0.5
			x0 := int(math.Floor(fx))
			wx := fx - float64(x0)
			if x0 < 0 {
				x0, wx = 0, 0
			}
			x1 := x0 + 1
			if x1 >= int(sw) {
				x1 = int(sw) - 1
			}
			sample := func(px, py int) (float64, float64, float64, float64) {
				offset := source.PixOffset(px, py)
				p := source.Pix[offset : offset+4]
				return float64(p[0]), float64(p[1]), float64(p[2]), float64(p[3])
			}
			r00, g00, b00, a00 := sample(x0, y0)
			r10, g10, b10, a10 := sample(x1, y0)
			r01, g01, b01, a01 := sample(x0, y1)
			r11, g11, b11, a11 := sample(x1, y1)
			blend := func(v00, v10, v01, v11 float64) uint8 {
				top := v00 + (v10-v00)*wx
				bottom := v01 + (v11-v01)*wx
				return uint8(math.Round(top + (bottom-top)*wy))
			}
			offset := dst.PixOffset(x, y)
			red := float64(blend(r00, r10, r01, r11))
			green := float64(blend(g00, g10, g01, g11))
			blue := float64(blend(b00, b10, b01, b11))
			alpha := float64(blend(a00, a10, a01, a11))
			// The window background is solid, so composite the icon onto it and
			// upload an opaque bitmap. This avoids relying on GDI's alpha semantics.
			background := 1 - alpha/255
			dst.Pix[offset] = uint8(math.Round(red + 246*background))
			dst.Pix[offset+1] = uint8(math.Round(green + 247*background))
			dst.Pix[offset+2] = uint8(math.Round(blue + 249*background))
			dst.Pix[offset+3] = 255
		}
	}
	return dst
}

func createIconHandle(source *image.RGBA) uintptr {
	size := source.Bounds().Dx()
	if size <= 0 || source.Bounds().Dy() != size {
		return 0
	}

	info := bitmapInfo{
		bmiHeader: bitmapInfoHeader{
			biSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			biWidth:       int32(size),
			biHeight:      -int32(size),
			biPlanes:      1,
			biBitCount:    32,
			biCompression: 0,
			biSizeImage:   uint32(size * size * 4),
		},
	}
	var bits unsafe.Pointer
	color, _, _ := procCreateDIBSection.Call(
		0,
		uintptr(unsafe.Pointer(&info)),
		0,
		uintptr(unsafe.Pointer(&bits)),
		0,
		0,
	)
	if color == 0 || bits == nil {
		return 0
	}
	defer procDeleteObject.Call(color)

	pixels := unsafe.Slice((*byte)(bits), size*size*4)
	for i := 0; i < size*size; i++ {
		offset := i * 4
		pixels[offset] = source.Pix[offset+2]
		pixels[offset+1] = source.Pix[offset+1]
		pixels[offset+2] = source.Pix[offset]
		pixels[offset+3] = source.Pix[offset+3]
	}

	mask, _, _ := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, 0)
	if mask == 0 {
		return 0
	}
	defer procDeleteObject.Call(mask)

	iconInfo := iconInfo{
		fIcon:    1,
		hbmMask:  mask,
		hbmColor: color,
	}
	handle, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&iconInfo)))
	return handle
}
