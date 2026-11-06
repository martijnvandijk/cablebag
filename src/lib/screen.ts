// Drawing of a streamed remote screen (VNC and the Linux Remote Desktop engine) on a canvas.
// The binary message layout is documented at the top of src-tauri/src/vnc.rs.

import { writeText } from "./clipboard";

/** Paints one message; returns the new desktop size when the message was `size`. */
export function paint(buf: ArrayBuffer, canvas: HTMLCanvasElement, clipboardToPc: boolean): { w: number; h: number } | null {
  const v = new DataView(buf);
  const t = v.getUint8(0);
  const u = (i: number) => v.getUint16(1 + i * 2, true);
  if (t === 1) {
    canvas.width = u(0);
    canvas.height = u(1);
    canvas.getContext("2d");
    return { w: canvas.width, h: canvas.height };
  }
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  if (t === 2) {
    const [x, y, w, h] = [u(0), u(1), u(2), u(3)];
    if (!w || !h) return null;
    const px = new Uint8ClampedArray(buf, 9, w * h * 4);
    for (let i = 3; i < px.length; i += 4) px[i] = 255;
    ctx.putImageData(new ImageData(px, w, h), x, y);
  } else if (t === 3) {
    const [dx, dy, w, h, sx, sy] = [u(0), u(1), u(2), u(3), u(4), u(5)];
    ctx.drawImage(canvas, sx, sy, w, h, dx, dy, w, h);
  } else if (t === 4) {
    const [x, y] = [u(0), u(1)];
    createImageBitmap(new Blob([new Uint8Array(buf, 9)], { type: "image/jpeg" })).then((img) => ctx?.drawImage(img, x, y));
  } else if (t === 6 && clipboardToPc) {
    writeText(new TextDecoder().decode(new Uint8Array(buf, 1)));
  }
  return null;
}

/** Where a mouse event points, in pixels of the remote desktop. */
export function screenPos(canvas: HTMLCanvasElement, size: { w: number; h: number }, e: MouseEvent): [number, number] {
  const r = canvas.getBoundingClientRect();
  const x = Math.round(((e.clientX - r.left) / r.width) * size.w);
  const y = Math.round(((e.clientY - r.top) / r.height) * size.h);
  return [Math.max(0, Math.min(size.w - 1, x)), Math.max(0, Math.min(size.h - 1, y))];
}

/** The pressed-button mask bit of a DOM mouse button (VNC order: left, middle, right). */
export function buttonBit(b: number): number {
  return b === 0 ? 1 : b === 1 ? 2 : b === 2 ? 4 : 0;
}
