///////////////////////////////////////imports////////////////////////////////////////
import { settings } from './main.js';

///////////////////////////////////ball modelisation//////////////////////////////////
export let ball = new THREE.Mesh();
export function initBall(){
	// Create ball
	const ballGeometry = new THREE.SphereGeometry(0.2 * settings.ballSizeScale, 32, 32);
	const ballMaterial = new THREE.MeshPhongMaterial({ 
		color: 0xff0000,
		specular: 0x888888,
		shininess: 30
	});
	ball = new THREE.Mesh(ballGeometry, ballMaterial);
	ball.position.set(0, 1, 0); 
	ball.castShadow = true;
	ball.receiveShadow = true;
	ball.userData.heldBy = null; // Add this line to track which player is holding the ball
	settings.scene.add(ball);
}

export function clearBall(){
	settings.scene.remove(ball);
}
