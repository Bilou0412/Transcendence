///////////////////////////////////////imports////////////////////////////////////////
import { quitPong, settings, player1Paddle, player2Paddle } from './main.js';
import { ball } from './ball_init.js';
import { focusGame } from './monitor.js';
import { updatePaddleColor, pressedKeys } from './movements.js';
import { sleep } from './resetBall.js';

/////////////////////////////////////Keyboard/////////////////////////////////////////
export async function onKeyDown(event) {
    pressedKeys[event.key] = true;

    // Release the ball when space is pressed
	if (event.key === ' ' && ball.userData.heldBy !== null) {
        const direction = ball.userData.heldBy === 1 ? 1 : -1;
        settings.ballVelocity.set(direction * settings.ballSpeed * 8, 0, 0);
        const player = ball.userData.heldBy;
        ball.userData.heldBy = null;
        updatePaddleColor(player, player === 1 ? player1Paddle : player2Paddle);
    }

    if (event.key === 'Escape'){
        if ( settings.gameStatus === 'playing') {
            if (settings.displayStatus === 'settings'){
                clearModes();
                settingDisplay();
            }
            quitPong();
        } 
        else if ( settings.gameStatus === 'paused')
        {
            focusGame();
            await sleep(2000);
			settings.updateGameStatus('playing');
        }
    }
}

export function onKeyUp(event) {
    pressedKeys[event.key] = false;
}


/////////////////////////////////////Mouse/////////////////////////////////////////
export function onMouseWheel(event) {
    const zoomSpeed = 0.1;
    const zoomFactor = event.deltaY > 0 ? 1 + zoomSpeed : 1 - zoomSpeed;
    
    settings.camera.position.y *= zoomFactor;
    settings.camera.position.z *= zoomFactor;
    
    settings.camera.lookAt(0, 3, 6);
}
