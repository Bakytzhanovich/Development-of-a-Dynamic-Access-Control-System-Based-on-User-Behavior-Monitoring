/**
 * Lightweight 3D mouse-tilt for elements with class `.tilt-3d`.
 * Adds perspective-based rotateX/rotateY based on cursor position.
 *
 * Usage: <div class="card tilt-3d">…</div>
 */
(function () {
  const MAX_TILT = 6;     // degrees
  const SCALE = 1.01;
  const PERSPECTIVE = 1000;

  function attach(el) {
    if (el._tiltAttached) return;
    el._tiltAttached = true;
    el.style.transformStyle = 'preserve-3d';
    el.style.willChange = 'transform';

    let raf = null;
    let tx = 0, ty = 0;
    let curX = 0, curY = 0;

    function apply() {
      raf = null;
      curX += (tx - curX) * 0.18;
      curY += (ty - curY) * 0.18;
      el.style.transform = `perspective(${PERSPECTIVE}px) rotateX(${curY}deg) rotateY(${curX}deg) scale(${SCALE})`;
      if (Math.abs(tx - curX) > 0.01 || Math.abs(ty - curY) > 0.01) {
        raf = requestAnimationFrame(apply);
      }
    }

    el.addEventListener('mousemove', (e) => {
      const rect = el.getBoundingClientRect();
      const px = (e.clientX - rect.left) / rect.width;
      const py = (e.clientY - rect.top) / rect.height;
      tx = (px - 0.5) * MAX_TILT * 2;
      ty = -(py - 0.5) * MAX_TILT * 2;
      if (!raf) raf = requestAnimationFrame(apply);
    });

    el.addEventListener('mouseleave', () => {
      tx = 0; ty = 0;
      const reset = () => {
        curX += (0 - curX) * 0.18;
        curY += (0 - curY) * 0.18;
        el.style.transform = `perspective(${PERSPECTIVE}px) rotateX(${curY}deg) rotateY(${curX}deg) scale(1)`;
        if (Math.abs(curX) > 0.02 || Math.abs(curY) > 0.02) requestAnimationFrame(reset);
        else el.style.transform = '';
      };
      reset();
    });
  }

  function init() {
    document.querySelectorAll('.tilt-3d').forEach(attach);
    // Observe dynamically added nodes
    const obs = new MutationObserver((mutations) => {
      mutations.forEach((m) => {
        m.addedNodes.forEach((n) => {
          if (!(n instanceof HTMLElement)) return;
          if (n.classList && n.classList.contains('tilt-3d')) attach(n);
          n.querySelectorAll && n.querySelectorAll('.tilt-3d').forEach(attach);
        });
      });
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
