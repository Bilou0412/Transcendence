///////////////////////////////////////imports////////////////////////////////////////
import { player1UpBind, player1DownBind, player2UpBind, player2DownBind, player1Side, player2Side, player1Paddle, player2Paddle, settings } from './main.js';
import { ball } from './ball_init.js';
import { remoteWs } from './main.js';
// Object to track pressed keys
export const pressedKeys = {};

/////////////////////////////////////////cubes////////////////////////////////////////
export function updateCubeSelection() {
    settings.cubes.forEach(cube => {
        //update color depending on the side
        if (cube.userData.gridPosition.x < 2) {
            cube.material.color.setHex(player1Side);
        }
        else {
            cube.material.color.setHex(player2Side);
        }
        cube.userData.targetY = 0;
    });

    const updatePlayerCubes = (positions, player) => {
        const playerColor = player === 1 ? player1Paddle : player2Paddle;
        const color = ball.userData.heldBy === player ? 0x0aa23b : playerColor;
        positions.forEach((pos) => {
            const cube = settings.cubes.find(cube =>
                cube.userData.gridPosition.x === Math.floor(pos.x) &&
                cube.userData.gridPosition.z === Math.floor(pos.z)
            );
            if (cube) {
                cube.material.color.setHex(color);
                cube.userData.targetY = settings.targetHeight;
            }
        });
    };

    updatePlayerCubes(settings.player1Positions, 1);
    updatePlayerCubes(settings.player2Positions, 2);
}

////////////////////////////////////////paddles///////////////////////////////////////
export function movePlayerRemote (positions, centerZ) {
    const halfLength = Math.floor(positions.length / 2);
    const newPositions = positions.map((_, index) => ({
        x: positions[index].x,
        z: centerZ - halfLength + index
    }));

    console.log(newPositions);
    // Check if any cube in the line would go out of bounds
    if (newPositions.every(pos => pos.z >= 0 && pos.z < settings.platformLength)) {
        return newPositions;
    }
    return positions;
};

export function updatePlayerPositions() {
    const movePlayer = (positions, direction) => {
        const newPositions = positions.map(pos => ({
            x: pos.x,
            z: pos.z + direction * settings.moveSpeed
        }));

        // Check if any cube in the line would go out of bounds
        if (newPositions.every(pos => pos.z >= 0 && pos.z < settings.platformLength)) {
            return newPositions;
        }
        return positions;
    };


    if (settings.gameStatus === 'paused') {
        return;
    }
    if (settings.gameMode === 'remote 1v1') {
        let direction = 'none';
        if (pressedKeys[player1UpBind] || pressedKeys[player2UpBind]) {
            direction = 'up';
            // if (settings.remoteRole === 'left') {
            //     settings.updatePlayer1Positions(movePlayer(settings.player1Positions, -1));
            // } else {
            //     settings.updatePlayer2Positions(movePlayer(settings.player2Positions, -1));
            // }
        } else if (pressedKeys[player1DownBind] || pressedKeys[player2DownBind]) {
            direction = 'down';
            // if (settings.remoteRole === 'left') {
            //     settings.updatePlayer1Positions(movePlayer(settings.player1Positions, 1));
            // } else {
            //     settings.updatePlayer2Positions(movePlayer(settings.player2Positions, 1));
            // }
        }
        if (direction !== 'none') {
            remoteWs.send(JSON.stringify({
                event: 'paddle_moved',
                data: { direction: direction, role: settings.remoteRole }
            }));
        }
        return;
    }
    // Player 1 movement
    if (pressedKeys[player1UpBind])
		settings.updatePlayer1Positions(movePlayer(settings.player1Positions, -1));
    if (pressedKeys[player1DownBind])
		settings.updatePlayer1Positions(movePlayer(settings.player1Positions, 1));

    // Player 2 movement
    if (pressedKeys[player2UpBind])
		settings.updatePlayer2Positions(movePlayer(settings.player2Positions, -1));
    if (pressedKeys[player2DownBind])
		settings.updatePlayer2Positions(movePlayer(settings.player2Positions, 1));
}

export function updatePaddleColor(player, color) 
{
    const positions = player === 1 ? settings.player1Positions : settings.player2Positions;
    positions.forEach((pos) => {
        const cube = settings.cubes.find(cube =>
            cube.userData.gridPosition.x === Math.floor(pos.x) &&
            cube.userData.gridPosition.z === Math.floor(pos.z)
        );
        if (cube) {
            cube.material.color.setHex(color);
        }
    });
}