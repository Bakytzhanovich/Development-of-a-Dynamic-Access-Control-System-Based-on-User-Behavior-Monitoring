/**
 * Three.js animated background for Dynamic Access Control System.
 * Renders a wireframe icosahedron + particle field with mouse parallax.
 *
 * Usage:
 *   <canvas id="threeBg" data-mode="hero" data-color="0xFF3B47"></canvas>
 *   <script src="https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js"></script>
 *   <script src="/static/three-bg.js"></script>
 *
 * Modes:
 *   - hero    : login page, large vibrant centerpiece
 *   - ambient : dashboard / admin pages, subtler intensity
 */
(function () {
  function initThreeBg() {
    const canvas = document.getElementById('threeBg');
    if (!canvas || typeof THREE === 'undefined') return;

    const mode = canvas.dataset.mode || 'ambient';
    const accent = parseInt(canvas.dataset.color || '0xFF3B47', 16);
    const accentSoft = 0xFF8A8F;
    const cyan = 0x66E0FF;
    const isHero = mode === 'hero';

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05060B, isHero ? 0.04 : 0.05);

    const camera = new THREE.PerspectiveCamera(
      isHero ? 70 : 75,
      window.innerWidth / window.innerHeight,
      0.1,
      1000
    );
    camera.position.z = isHero ? 5.5 : 6.5;

    const renderer = new THREE.WebGLRenderer({
      canvas,
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Group to hold all rotating objects so we can apply a single tilt
    const group = new THREE.Group();
    scene.add(group);

    // Outer wireframe icosahedron
    const outerGeo = new THREE.IcosahedronGeometry(isHero ? 2.0 : 1.6, 1);
    const outerMat = new THREE.MeshBasicMaterial({
      color: accent,
      wireframe: true,
      transparent: true,
      opacity: isHero ? 0.42 : 0.22,
    });
    const outer = new THREE.Mesh(outerGeo, outerMat);
    group.add(outer);

    // Mid wireframe (offset rotation)
    const midGeo = new THREE.IcosahedronGeometry(isHero ? 1.35 : 1.05, 0);
    const midMat = new THREE.MeshBasicMaterial({
      color: accentSoft,
      wireframe: true,
      transparent: true,
      opacity: isHero ? 0.5 : 0.28,
    });
    const mid = new THREE.Mesh(midGeo, midMat);
    group.add(mid);

    // Inner glowing core
    const coreGeo = new THREE.IcosahedronGeometry(isHero ? 0.6 : 0.5, 0);
    const coreMat = new THREE.MeshBasicMaterial({
      color: accent,
      wireframe: true,
      transparent: true,
      opacity: isHero ? 0.85 : 0.55,
    });
    const core = new THREE.Mesh(coreGeo, coreMat);
    group.add(core);

    // Particle field
    const partCount = isHero ? 1100 : 700;
    const partGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(partCount * 3);
    const colors = new Float32Array(partCount * 3);
    const accentColor = new THREE.Color(accent);
    const cyanColor = new THREE.Color(cyan);
    const whiteColor = new THREE.Color(0xFFFFFF);

    for (let i = 0; i < partCount; i++) {
      const r = 3 + Math.random() * 10;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos((Math.random() * 2) - 1);
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);

      const roll = Math.random();
      let c;
      if (roll < 0.55) c = whiteColor;
      else if (roll < 0.85) c = accentColor;
      else c = cyanColor;
      colors[i * 3] = c.r;
      colors[i * 3 + 1] = c.g;
      colors[i * 3 + 2] = c.b;
    }
    partGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    partGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const partMat = new THREE.PointsMaterial({
      size: isHero ? 0.022 : 0.018,
      transparent: true,
      opacity: isHero ? 0.85 : 0.55,
      vertexColors: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });
    const particles = new THREE.Points(partGeo, partMat);
    scene.add(particles);

    // Orbital rings
    function makeRing(radius, opacity, color, tiltX, tiltZ) {
      const segments = 96;
      const ringGeo = new THREE.BufferGeometry();
      const ringPos = new Float32Array((segments + 1) * 3);
      for (let i = 0; i <= segments; i++) {
        const a = (i / segments) * Math.PI * 2;
        ringPos[i * 3] = Math.cos(a) * radius;
        ringPos[i * 3 + 1] = 0;
        ringPos[i * 3 + 2] = Math.sin(a) * radius;
      }
      ringGeo.setAttribute('position', new THREE.BufferAttribute(ringPos, 3));
      const ringMat = new THREE.LineBasicMaterial({
        color, transparent: true, opacity,
      });
      const ring = new THREE.Line(ringGeo, ringMat);
      ring.rotation.x = tiltX;
      ring.rotation.z = tiltZ;
      return ring;
    }

    if (isHero) {
      group.add(makeRing(2.6, 0.35, accent, Math.PI / 2.3, 0.4));
      group.add(makeRing(3.1, 0.22, accentSoft, Math.PI / 2.8, -0.3));
      group.add(makeRing(3.6, 0.15, cyan, Math.PI / 2.5, 0.7));
    } else {
      group.add(makeRing(2.0, 0.18, accent, Math.PI / 2.3, 0.4));
      group.add(makeRing(2.5, 0.10, cyan, Math.PI / 2.6, -0.2));
    }

    // Mouse parallax
    let mx = 0, my = 0;
    let targetX = 0, targetY = 0;
    window.addEventListener('mousemove', (e) => {
      targetX = (e.clientX / window.innerWidth - 0.5) * 0.6;
      targetY = (e.clientY / window.innerHeight - 0.5) * 0.6;
    });

    // Scroll-driven extra tilt (subtle)
    let scrollY = 0;
    window.addEventListener('scroll', () => {
      scrollY = window.scrollY * 0.0008;
    }, { passive: true });

    const clock = new THREE.Clock();
    function animate() {
      requestAnimationFrame(animate);
      const dt = clock.getDelta();

      // Ease toward target
      mx += (targetX - mx) * 0.05;
      my += (targetY - my) * 0.05;

      outer.rotation.x += dt * 0.12;
      outer.rotation.y += dt * 0.16;
      mid.rotation.x -= dt * 0.22;
      mid.rotation.y -= dt * 0.18;
      core.rotation.x += dt * 0.4;
      core.rotation.y -= dt * 0.35;

      group.rotation.x = my * 0.5 + scrollY;
      group.rotation.y = mx * 0.5;

      particles.rotation.y += dt * 0.02;
      particles.rotation.x = my * 0.15;

      // Subtle pulse on core
      const pulse = 1 + Math.sin(clock.elapsedTime * 1.6) * (isHero ? 0.08 : 0.04);
      core.scale.set(pulse, pulse, pulse);

      camera.position.x += (mx * 0.5 - camera.position.x) * 0.04;
      camera.position.y += (-my * 0.5 - camera.position.y) * 0.04;
      camera.lookAt(scene.position);

      renderer.render(scene, camera);
    }

    function onResize() {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    }
    window.addEventListener('resize', onResize);

    // Critical state hook — pages can trigger this to make the bg pulse red
    window.setThreeCritical = function (active) {
      const target = active ? 1.6 : 1.0;
      outerMat.opacity = (isHero ? 0.42 : 0.22) * target;
      midMat.opacity = (isHero ? 0.5 : 0.28) * target;
      coreMat.opacity = (isHero ? 0.85 : 0.55) * target;
    };

    animate();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initThreeBg);
  } else {
    initThreeBg();
  }
})();
