///////////////////////////////////////imports////////////////////////////////////////
import { player1Paddle, player2Paddle, settings} from "./main.js";
import { ball} from "./ball_init.js";
import { updatePaddleColor } from "./movements.js";
import { updateHitCounter1Display, updateHitCounter2Display } from "./display.js";


////////////////////////////////////////reset/////////////////////////////////////////
export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function resetBall() {
    if (!settings)
        return;
    ball.position.set(0, 1, 0.5);
	settings.updateBallSpeed(0); // Réinitialise la vitesse de la balle
    settings.ballVelocity.set(0, 0, 0); // Pas de mouvement initial
    ball.userData.heldBy = null;
	settings.updatePlayer1HitCounter(0); // Réinitialise le compteur de hits du joueur 1
	settings.updatePlayer2HitCounter(0); // Réinitialise le compteur de hits du joueur 2
    updateHitCounter1Display();
    updateHitCounter2Display();
    updatePaddleColor(1, player1Paddle); // Réinitialise la couleur du paddle du joueur 1
    updatePaddleColor(2, player2Paddle); // Réinitialise la couleur du paddle du joueur 2

    await sleep(2000);

    if (!settings)
        return;
	settings.updateBallSpeed(settings.initialBallSpeed); // Réinitialise la vitesse de la balle
	settings.updateBallVelocity(new THREE.Vector3(settings.ballSpeed * (settings.ServSide == 1 ? -1 : 1), 0, settings.ballSpeed * (Math.random() > 0.5 ? 1 : -1)));
	// settings.updateBallVelocity(new THREE.Vector3(settings.ballSpeed * (settings.ServSide == 1 ? -1 : 1), 0, 0));

}
