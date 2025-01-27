///////////////////////////////////////imports////////////////////////////////////////
import { settings} from './main.js';


/////////////////////////////////////scoreboard///////////////////////////////////////
let scoreDisplayCtx = null;
let scoreDisplay = null;
let scoreDisplayTexture = null;
let scoreboardMesh = null;
let scoreDisplayMesh = null;
export function initScoreboard(){
	// Load the scoreboard image texture
	const scoreboardTexture = new THREE.TextureLoader().load('texture/Scoreboard.png');
	const scoreboardMaterial = new THREE.MeshBasicMaterial({ map: scoreboardTexture });

	// Create the scoreboard plane
	const scoreboardWidth = 20; // Adjust the width as needed
	const scoreboardHeight = 10; // Adjust the height as needed
	const scoreboardGeometry = new THREE.PlaneGeometry(scoreboardWidth, scoreboardHeight);
	scoreboardMesh = new THREE.Mesh(scoreboardGeometry, scoreboardMaterial);
	scoreboardMesh.position.set(0, 10, -settings.platformLength / 2 - 2); // Adjust the position as needed
	settings.scene.add(scoreboardMesh);

	scoreDisplay = document.createElement('canvas');
	scoreDisplay.width = 1200;
	scoreDisplay.height = 600;
	scoreDisplayCtx = scoreDisplay.getContext('2d');

	scoreDisplayTexture = new THREE.CanvasTexture(scoreDisplay);

	const scoreDisplayMaterial = new THREE.MeshBasicMaterial({ map: scoreDisplayTexture, transparent: true });
	const scoreDisplayPlane = new THREE.PlaneGeometry(2, 1);
	scoreDisplayMesh = new THREE.Mesh(scoreDisplayPlane, scoreDisplayMaterial);
	scoreDisplayMesh.scale.set(10, 10, 10);
	scoreDisplayMesh.position.set(0, 10, -settings.platformLength / 2 - 1.9);
	settings.scene.add(scoreDisplayMesh);
}

export const updateScoreDisplay = () => {
    scoreDisplayCtx.clearRect(0, 0, scoreDisplay.width, scoreDisplay.height);
    scoreDisplayCtx.fillStyle = 'white';
    scoreDisplayCtx.font = 'bold 100px "Digital-7"';

    // Calculate text widths for each part of the scoreboard
    const player1ScoreText = `${settings.player1Score}`;
    const player2ScoreText = `${settings.player2Score}`;


    // Draw the scores and separator at calculated positions
    scoreDisplayCtx.fillText(player1ScoreText, 300, 300);
    scoreDisplayCtx.fillText(player2ScoreText, 850, 300);

    // Update the texture to reflect the new score
    scoreDisplayTexture.needsUpdate = true;
};


/////////////////////////////////////clock///////////////////////////////////////
let ClockCtx = null;
let Clock = null;
let ClockTexture = null;
let ClockMesh = null;
export function initClock(){

	Clock = document.createElement('canvas');
	Clock.width = 1200;
	Clock.height = 600;
	ClockCtx = Clock.getContext('2d');

	ClockTexture = new THREE.CanvasTexture(Clock);
	const ClockMaterial = new THREE.MeshBasicMaterial({ map: ClockTexture, transparent: true });
	const ClockPlane = new THREE.PlaneGeometry(2, 1);
	ClockMesh = new THREE.Mesh(ClockPlane, ClockMaterial);
	ClockMesh.scale.set(10, 10, 10);
	ClockMesh.position.set(0, 10, -settings.platformLength / 2 - 1.9);
	settings.scene.add(ClockMesh);
};

export const updateClock = () => {
    if (!settings)
    {
        return;
    }
	ClockCtx.clearRect(0, 0, Clock.width, Clock.height);
	ClockCtx.fillStyle = 'white';
	ClockCtx.font = 'bold 100px "Digital-7"';

	const elapsedTime = Math.floor((Date.now() - settings.gameStartTime) / 1000); // Get elapsed time
	const minutes = Math.floor(elapsedTime / 60);
	const seconds = elapsedTime % 60;
	
	const formattedTime = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
	
	// Draw the scores and separator at calculated positions
	ClockCtx.fillText(formattedTime, 500, 100);

	// Update the texture to reflect the new score
    ClockTexture.needsUpdate = true;
    setTimeout(updateClock, 1000);
};


////////////////////////////////////Hit Counters//////////////////////////////////////
let charge1 = null;
let charge2 = null;
export function updateHitCounter1Display() {
    // Remove the previous charge1 rectangle
    if (charge1) {
        settings.scene.remove(charge1);
        charge1 = null;
    }

    if (settings.player1HitCounter > 0) {
        const length_max = 5.5;
        const width_max = 0.5;
        const length = length_max * (settings.player1HitCounter / settings.superChargeCount);
        const charge1Geometry = new THREE.PlaneGeometry(length, width_max); // Width and height of the charge1
        const charge1Material = new THREE.MeshBasicMaterial({ color: 0xff0000, side: THREE.DoubleSide });
        charge1 = new THREE.Mesh(charge1Geometry, charge1Material);

        // Set the position of the charge1
        const middle = -4.75;
        const x = middle - (length_max / 2) + (length / 2);
        charge1.position.set(x, 8.25, -settings.platformLength / 2 - 1.9); // Adjust the position as needed

        // Add the charge1 to the scene
        settings.scene.add(charge1);
    }
}

export function updateHitCounter2Display() {
    // Remove the previous charge2 rectangle
    if (charge2) {
        settings.scene.remove(charge2);
        charge2 = null;
    }

    if (settings.player2HitCounter > 0) {
        const length_max = 5.5;
        const width_max = 0.5;
        const length = length_max * (settings.player2HitCounter / settings.superChargeCount);
        const charge2Geometry = new THREE.PlaneGeometry(length, width_max); // Width and height of the charge2
        const charge2Material = new THREE.MeshBasicMaterial({ color: 0xff0000, side: THREE.DoubleSide });
        charge2 = new THREE.Mesh(charge2Geometry, charge2Material);

        // Set the position of the charge2
        const middle = 4.75;
        const x = middle - (length_max / 2) + (length / 2);
        charge2.position.set(x, 8.25, -settings.platformLength / 2 - 1.9); // Adjust the position as needed

        // Add the charge2 to the scene
        settings.scene.add(charge2);
    }
}

//////////////////////////////////////Clear whole Scoreboard//////////////////////////////////////
export function clearScoreboard(){
    settings.scene.remove(scoreDisplayMesh);
    settings.scene.remove(scoreboardMesh);
    settings.scene.remove(ClockMesh);
}
