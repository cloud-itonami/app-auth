<script lang="ts">
	import { onMount } from 'svelte';
	import { theme } from '$lib/theme';

	let canvas: HTMLCanvasElement;

	onMount(() => {
		const ctx = canvas.getContext('2d');
		if (!ctx) return;

		const darkColors = ['#58CC02', '#6366f1', '#1CB0F6', '#8EE000', '#818cf8'];
		const lightColors = ['#4ade80', '#6366f1', '#38bdf8', '#a3e635', '#a78bfa'];

		let W: number, H: number;

		interface Particle {
			x: number; y: number; r: number;
			dx: number; dy: number; a: number; ci: number;
		}

		const initW = innerWidth || 1920;
		const initH = innerHeight || 1080;
		const particles: Particle[] = [];
		for (let i = 0; i < 40; i++) {
			particles.push({
				x: Math.random() * initW, y: Math.random() * initH,
				r: Math.random() * 2.5 + 0.5,
				dx: (Math.random() - 0.5) * 0.3,
				dy: -(Math.random() * 0.4 + 0.1),
				a: Math.random() * 0.4 + 0.1,
				ci: i % 5
			});
		}

		function resize() { W = canvas.width = innerWidth; H = canvas.height = innerHeight; }
		resize();
		window.addEventListener('resize', resize);

		let currentTheme = 'dark';
		const unsub = theme.subscribe((t) => { currentTheme = t; });

		let raf: number;
		function draw() {
			ctx!.clearRect(0, 0, W, H);
			const colors = currentTheme === 'dark' ? darkColors : lightColors;
			for (const p of particles) {
				p.x += p.dx; p.y += p.dy;
				if (p.y < -10) { p.y = H + 10; p.x = Math.random() * W; }
				if (p.x < -10) p.x = W + 10;
				if (p.x > W + 10) p.x = -10;
				ctx!.beginPath();
				ctx!.arc(p.x, p.y, p.r, 0, Math.PI * 2);
				ctx!.fillStyle = colors[p.ci];
				ctx!.globalAlpha = currentTheme === 'dark' ? p.a : p.a * 0.6;
				ctx!.fill();
			}
			ctx!.globalAlpha = 1;
			raf = requestAnimationFrame(draw);
		}
		draw();

		return () => {
			cancelAnimationFrame(raf);
			window.removeEventListener('resize', resize);
			unsub();
		};
	});
</script>

<canvas bind:this={canvas} class="fixed inset-0 w-full h-full z-0 pointer-events-none"></canvas>
