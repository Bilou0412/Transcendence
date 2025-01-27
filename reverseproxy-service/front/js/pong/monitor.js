///////////////////////////////////////imports////////////////////////////////////////
import { settings } from './main.js';

/////////////////////////////////////Table////////////////////////////////////////
export function initTable()
{
    const glftLoader = new THREE.GLTFLoader();
    glftLoader.load('./models/table/scene.gltf', (gltfScene) => {
        // Set position and scale of the model
        gltfScene.scene.position.y = -57;
        // gltfScene.scene.position.z = settings.platformLength / 2 + 6;
        gltfScene.scene.scale.set(30, 30, 30);

        settings.scene.add(gltfScene.scene);

    });
}

///////////////////////////////////////monitor////////////////////////////////////////
let MonitorDisplay = null;
let MonitorDisplayCtx = null;
let MonitorDisplayTexture = null;
export function initMonitor(){
	const glftLoader = new THREE.GLTFLoader();
    glftLoader.load('./models/dell_monitor/scene.gltf', (gltfScene) => {
        gltfScene.scene.position.z = settings.platformLength / 2 + 6;
        gltfScene.scene.scale.set(0.01, 0.0086, 0.01);

        settings.scene.add(gltfScene.scene);

    });
	
	MonitorDisplay = document.createElement('canvas');
	MonitorDisplay.width = 500;
	MonitorDisplay.height = 300;
	MonitorDisplayCtx = MonitorDisplay.getContext('2d');

	MonitorDisplayTexture = new THREE.CanvasTexture(MonitorDisplay);
	const MonitorDisplayMaterial = new THREE.MeshBasicMaterial({ map: MonitorDisplayTexture, transparent: true });
	const MonitorDisplayPlane = new THREE.PlaneGeometry(2, 1);
	const MonitorDisplayMesh = new THREE.Mesh(MonitorDisplayPlane, MonitorDisplayMaterial);
	MonitorDisplayMesh.scale.set(2, 3, 3);
	MonitorDisplayMesh.position.set(-0.2, 2.5, settings.platformLength / 2 + 6.1);
	settings.scene.add(MonitorDisplayMesh);
}


/////////////////////////////////////View Focus///////////////////////////////////////
export function focusGame() {
	// Define target positions and orientations for each focus
	const gameView = {
		position: { x: 0, y: settings.platformWidth * 0.6, z: settings.platformLength * 1},
		rotation: { x: -0.9, y: 0, z: 0 }
	};

    gsap.to(settings.camera.position, {
        duration: 2,  // Duration of the animation in seconds
        x: gameView.position.x,
        y: gameView.position.y,
        z: gameView.position.z,
        ease: "power2.inOut"
    });

    gsap.to(settings.camera.rotation, {
        duration: 2,
        x: gameView.rotation.x,
        y: gameView.rotation.y,
        z: gameView.rotation.z,
        ease: "power2.inOut"
    });
    // Move the light with the camera
    settings.updateDirectionalLightSmoothly(gameView.position);
}

export function focusMonitor() {
	const monitorView = {
		position: { x: 0, y: 2.7, z: 22.75 },
		rotation: { x: -0, y: 0, z: 0 }
	};
	
    gsap.to(settings.camera.position, {
        duration: 2,
        x: monitorView.position.x,
        y: monitorView.position.y,
        z: monitorView.position.z,
        ease: "power2.inOut"
    });

    gsap.to(settings.camera.rotation, {
        duration: 2,
        x: monitorView.rotation.x,
        y: monitorView.rotation.y,
        z: monitorView.rotation.z,
        ease: "power2.inOut"
    });
    // Move the light with the camera
    settings.updateDirectionalLightSmoothly(monitorView.position);
}