import { settings } from "./main.js";

function initScreenBackground() {
    const ScreenBackgroundTexture = new THREE.TextureLoader().load('../../texture/pong_screen.png');
	const ScreenBackgroundMaterial = new THREE.MeshBasicMaterial({ map: ScreenBackgroundTexture });
	const ScreenBackgroundPlane = new THREE.PlaneGeometry(2, 0.975);
	const ScreenBackgroundMesh = new THREE.Mesh(ScreenBackgroundPlane, ScreenBackgroundMaterial);
    ScreenBackgroundMesh.scale.set(2.53, 2.53, 2.53);
	ScreenBackgroundMesh.position.set(-0.03, 2.72, settings.platformLength / 2 + 6.1);
	settings.scene.add(ScreenBackgroundMesh);
}

export function titleDisplay() {
    initScreenBackground();
}
