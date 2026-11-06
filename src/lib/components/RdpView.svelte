<script lang="ts">
  import type { Snippet } from "svelte";
  import { onMount, onDestroy } from "svelte";
  import { listen } from "@tauri-apps/api/event";
  import { api, Channel } from "../api";
  import { app, type Tab } from "../state.svelte";
  import { menu } from "../menu.svelte";
  import { tiles } from "../tiles.svelte";
  import { isAppShortcut } from "../shortcuts";
  import { paint, screenPos, buttonBit } from "../screen";
  import { Keyboard, RotateCw, Unplug, Monitor, Maximize, Minimize } from "@lucide/svelte";

  /** In tiling the bar doubles as the pane header: pane is its name part, paneEnd its buttons. */
  let { tab, visible, pane, paneEnd }: { tab: Tab; visible: boolean; pane?: Snippet<[Tab]>; paneEnd?: Snippet<[Tab]> } = $props();
  let area: HTMLDivElement;
  let message = $state("");
  let log = $state<string[]>([]);
  let opened = false;
  // The native window is shown once the control has something to show: a Windows prompt or the desktop.
  let nativeUp = $state(false);
  // Outside Windows the engine draws here instead (Windows never sends frame messages).
  let canvas: HTMLCanvasElement;
  let size = $state({ w: 0, h: 0 });
  let fit = $state(true);
  let room = $state({ w: 0, h: 0 });
  let dpr = $state(window.devicePixelRatio || 1);
  let buttons = 0;

  // Fit: as large as the tab allows, up or down, keeping the shape. Real size: one remote pixel on one
  // screen pixel, so with Windows display scaling the canvas is smaller in CSS pixels.
  const view = $derived.by(() => {
    if (!size.w || !size.h) return { w: 0, h: 0 };
    if (!fit) return { w: size.w / dpr, h: size.h / dpr };
    const k = Math.min(room.w / size.w, room.h / size.h);
    return k > 0 ? { w: Math.floor(size.w * k), h: Math.floor(size.h * k) } : { w: size.w / dpr, h: size.h / dpr };
  });

  function rect() {
    const r = area.getBoundingClientRect();
    const d = window.devicePixelRatio || 1;
    return { x: Math.round(r.left * d), y: Math.round(r.top * d), w: Math.round(r.width * d), h: Math.round(r.height * d) };
  }

  const show = $derived(
    visible && !app.overlay && !menu.open && (tab.status === "connected" || (tab.status === "connecting" && nativeUp)),
  );

  $effect(() => {
    void tiles.version;
    if (opened) api.rdpVisible(tab.id, show).catch(() => {});
    if (show) requestAnimationFrame(() => api.rdpBounds(tab.id, rect()));
  });

  // Input goes out strictly in order; separate invokes could otherwise overtake each other.
  let queue: Promise<unknown> = Promise.resolve();
  const input = (action: Record<string, unknown>) => {
    queue = queue.then(() => api.rdpScreen(tab.id, action).catch(() => {}));
  };

  // Keys travel as DOM codes: the engine turns them into remote scan codes, so the remote keyboard layout rules.
  const pressed = new Set<string>();
  function keyDown(e: KeyboardEvent) {
    if (isAppShortcut(e)) return; // Cablebag's own shortcuts are not sent to the remote screen
    e.preventDefault();
    if (pressed.has(e.code)) return; // auto-repeat is a held key, not extra presses
    pressed.add(e.code);
    input({ cmd: "key", code: e.code, down: true });
  }
  function keyUp(e: KeyboardEvent) {
    if (!pressed.delete(e.code)) return;
    e.preventDefault();
    input({ cmd: "key", code: e.code, down: false });
  }
  function releaseAll() {
    for (const c of pressed) input({ cmd: "key", code: c, down: false });
    pressed.clear();
  }

  function handle(buf: ArrayBuffer) {
    const s = paint(buf, canvas, false);
    if (s) size = s;
  }

  function pos(e: MouseEvent): [number, number] {
    return screenPos(canvas, size, e);
  }

  const bit = buttonBit;

  onMount(() => {
    const ro = new ResizeObserver(([e]) => {
      room = { w: e.contentRect.width, h: e.contentRect.height };
      dpr = window.devicePixelRatio || 1;
      if (opened && area.offsetWidth) api.rdpBounds(tab.id, rect()).catch(() => {});
    });
    ro.observe(area);
    const un = listen<{ id: string; event: string; text: string }>("rdp-event", (e) => {
      if (e.payload.id !== tab.id) return;
      if (e.payload.event === "log" && e.payload.text) log = [...log.slice(-6), e.payload.text];
      // A click on the remote screen: this pane becomes the active one.
      if (e.payload.event === "activated" && app.activeId !== tab.id) app.activeId = tab.id;
      if (e.payload.event === "disconnected") {
        message = e.payload.text || "The remote desktop session ended.";
        nativeUp = false;
      }
      if (["auth-warning", "connected", "login", "logon-error"].includes(e.payload.event)) nativeUp = true;
    });
    const us = listen<{ id: string; state: string; message: string }>("term-status", (e) => {
      if (e.payload.id === tab.id && e.payload.message) message = e.payload.message;
    });
    message = "";
    const ch = new Channel<ArrayBuffer>();
    ch.onmessage = handle;
    // The remote desktop gets the size of the pane when it connects, and not every server can change it later:
    // wait (up to 3 seconds) until the pane is laid out, or a new pane would ask for a tiny desktop.
    const laidOut = async () => {
      const until = Date.now() + 3000;
      while ((area.offsetWidth < 100 || area.offsetHeight < 100) && Date.now() < until) await new Promise((r) => setTimeout(r, 50));
    };
    laidOut()
      .then(() => api.rdpOpen(tab.id, $state.snapshot(tab.session!), rect(), Math.round((window.devicePixelRatio || 1) * 100), ch))
      .then(() => (opened = true))
      .catch((e) => {
        message = String(e);
        tab.status = "failed";
      });
    return () => {
      ro.disconnect();
      un.then((f) => f());
      us.then((f) => f());
    };
  });

  onDestroy(() => api.rdpClose(tab.id).catch(() => {}));

  $effect(() => {
    if (visible && tab.status === "connected" && app.activeId === tab.id && size.w) setTimeout(() => canvas?.focus(), 30);
  });

  const s = $derived(tab.session!);
</script>

<div class="rdp" style:display={visible ? "flex" : "none"}>
  <div class="bar">
    {#if pane}
      {@render pane(tab)}
    {:else}
      <Monitor size={14} />
      <span class="where">{s.username ? `${s.username} on ` : ""}{s.host}</span>
      <span class="spacer"></span>
    {/if}
    {#if size.w}
      <button class="btn small" title={fit ? "Show at real size" : "Fit to the tab"} onclick={() => (fit = !fit)}>
        {#if fit}<Maximize size={14} /><span class="lbl">Real size</span>{:else}<Minimize size={14} /><span class="lbl">Fit</span>{/if}
      </button>
    {/if}
    <button class="btn small" disabled={tab.status !== "connected"} onclick={() => api.rdpCommand(tab.id, "cad")} title="Send Ctrl+Alt+Del to the remote computer">
      <Keyboard size={14} /><span class="lbl">Ctrl+Alt+Del</span>
    </button>
    <button class="btn small" onclick={() => app.restart(tab.id)} title="Connect again"><RotateCw size={14} /><span class="lbl">Reconnect</span></button>
    <button class="btn small" disabled={tab.status !== "connected"} onclick={() => api.rdpCommand(tab.id, "disconnect")} title="End the remote session">
      <Unplug size={14} /><span class="lbl">Disconnect</span>
    </button>
    {#if paneEnd}{@render paneEnd(tab)}{/if}
  </div>
  <div class="area" class:fit bind:this={area}>
    <canvas
      bind:this={canvas}
      data-screen={tab.id}
      style:width="{view.w}px"
      style:height="{view.h}px"
      tabindex="0"
      style:display={size.w && tab.status === "connected" ? "block" : "none"}
      onkeydown={keyDown}
      onkeyup={keyUp}
      onblur={releaseAll}
      onmousemove={(e) => {
        const [x, y] = pos(e);
        input({ cmd: "pointer", x, y, buttons });
      }}
      onmousedown={(e) => {
        canvas.focus();
        buttons |= bit(e.button);
        const [x, y] = pos(e);
        input({ cmd: "pointer", x, y, buttons });
      }}
      onmouseup={(e) => {
        buttons &= ~bit(e.button);
        const [x, y] = pos(e);
        input({ cmd: "pointer", x, y, buttons });
      }}
      oncontextmenu={(e) => e.preventDefault()}
      onwheel={(e) => {
        e.preventDefault();
        const [x, y] = pos(e);
        const w = e.deltaY < 0 ? 8 : 16;
        input({ cmd: "pointer", x, y, buttons: buttons | w });
        input({ cmd: "pointer", x, y, buttons });
      }}
    ></canvas>
    {#if tab.status !== "connected" && !show}
      <div class="state">
        {#if tab.status === "connecting"}
          <p>Connecting to <strong>{s.host}</strong>...</p>
        {:else}
          <p>{message || "Not connected."}</p>
          <button class="btn primary" onclick={() => app.restart(tab.id)}><RotateCw size={14} /> Connect again</button>
        {/if}
        {#each log as l}<p class="log mono">{l}</p>{/each}
      </div>
    {:else if !show && !size.w && visible}
      <div class="state"><p class="muted">The remote screen is hidden while a dialog is open.</p></div>
    {/if}
  </div>
</div>

<style>
  .rdp {
    position: absolute;
    inset: 0;
    container-type: inline-size;
    flex-direction: column;
    background: var(--bg);
  }
  .bar {
    white-space: nowrap;
    overflow: hidden;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 10px;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
    color: var(--muted);
  }
  .where {
    color: var(--text);
  }
  .spacer {
    flex: 1;
  }
  .small {
    padding: 3px 9px;
    font-size: 12px;
  }
  .btn.small {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    flex-shrink: 0;
  }
  /* In a narrow pane only the icons stay; the pane header already names the tab. */
  @container (max-width: 640px) {
    .lbl,
    .where {
      display: none;
    }
  }

  .area {
    position: relative;
    flex: 1;
    min-height: 0;
    display: flex;
    overflow: auto;
    background: #1d1c1a;
  }
  .area.fit {
    overflow: hidden;
  }
  canvas {
    /* Centred while it fits, scrollable from the top left when it does not. */
    margin: auto;
    flex-shrink: 0;
    outline: none;
    cursor: default;
    image-rendering: auto;
  }
  .state {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    color: #ebe7df;
    text-align: center;
    padding: 20px;
  }
  .log {
    margin: 0;
    font-size: 11px;
    color: #a39e93;
  }
</style>
