///////////////////////////////////////imports////////////////////////////////////////
import { settings } from "./main.js";
import { pongColors } from "./pong_bind.js";


//////////////////////////////////////cubes modelisation//////////////////////////////////////
export const createRoundedBox = (width, height, depth, radius, smoothness) => {
    const shape = new THREE.Shape();
    // epsilon to prevent rendering errors
    const eps = 0.00001;
    const radius0 = radius - eps;
    //shape each corner as quarter circle
    shape.absarc(eps, eps, eps, -Math.PI / 2, -Math.PI, true);
    shape.absarc(eps, height - radius * 2, eps, Math.PI, Math.PI / 2, true);
    shape.absarc(width - radius * 2, height - radius * 2, eps, Math.PI / 2, 0, true);
    shape.absarc(width - radius * 2, eps, eps, 0, -Math.PI / 2, true);
    //extrude the shape to the depth
    const geometry = new THREE.ExtrudeBufferGeometry(shape, {
        depth: depth - radius0 * 2,
        bevelEnabled: true,
        bevelSegments: smoothness * 2,
        steps: 1,
        bevelSize: radius,
        bevelThickness: radius0,
        curveSegments: smoothness
    });
    geometry.center();
    return geometry;
};


//////////////////////////////////////cubes creation//////////////////////////////////////
export function initSides(){
	// Left side cubes
	for (let i = -1; i < 2; i++) {
		for (let j = -1; j < settings.platformLength + 1; j++) {
			const geometry = createRoundedBox(settings.cubeSize, settings.cubeSize, settings.cubeSize, 0.18, 4);
			const material = new THREE.MeshPhongMaterial({ color: pongColors.player1Side });
			const cube = new THREE.Mesh(geometry, material);
			cube.position.set(i - settings.platformWidth / 2 + 0.5, 0, j - settings.platformLength / 2 + 0.5);
			cube.userData.gridPosition = { x: i, z: j };
			settings.cubes.push(cube);
			settings.scene.add(cube);
		}
	}

	// Right side cubes
	for (let i = settings.platformWidth - 2; i < settings.platformWidth + 1; i++) {
		for (let j = -1; j < settings.platformLength + 1; j++) {
			const geometry = createRoundedBox(settings.cubeSize, settings.cubeSize, settings.cubeSize, 0.18, 4);
			const material = new THREE.MeshPhongMaterial({ color: pongColors.player2Side });
			const cube = new THREE.Mesh(geometry, material);
			cube.position.set(i - settings.platformWidth / 2 + 0.5, 0, j - settings.platformLength / 2 + 0.5);
			cube.userData.gridPosition = { x: i, z: j };
			settings.cubes.push(cube);
			settings.scene.add(cube);
		}
	}
}

export function clearSides(){
	settings.cubes.forEach(cube => {
		settings.scene.remove(cube);
	});
	settings.cubes = [];
}

let platform = null;
export function initMiddlePlatform(){
	// Load the textures
	const textureLoader = new THREE.TextureLoader();
	const platformTexture = textureLoader.load('texture/50x30.png');
	const sideTexture = textureLoader.load('texture/side50.png');

	// Create materials
	const platformMaterial = new THREE.MeshPhongMaterial({ map: platformTexture });
	// platformMaterial.map.minFilter = THREE.LinearFilter;
	const sideMaterial = new THREE.MeshPhongMaterial({ map: sideTexture });

	// Create an array of materials for each face of the box
	const materials = [
		sideMaterial, // Right side
		sideMaterial, // Left side
		platformMaterial, // Top side
		sideMaterial, // Bottom side
		sideMaterial, // Front side
		sideMaterial  // Back side
	];

	// Create middle platform with different textures
	const platformGeometry = new THREE.BoxGeometry(settings.platformWidth - 4, settings.cubeSize, settings.platformLength + 2);
	platform = new THREE.Mesh(platformGeometry, materials);
	settings.scene.add(platform);
}


export function clearMiddle(){
	settings.scene.remove(platform);
}