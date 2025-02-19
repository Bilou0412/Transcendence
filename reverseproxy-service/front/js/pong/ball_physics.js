///////////////////////////////////////imports////////////////////////////////////////
import { settings, quit } from './main.js';
import { ball } from './ball_init.js';
import { updatePaddleColor } from './movements.js';
import { resetBall } from './resetBall.js';
import { updateScoreDisplay, updateHitCounter1Display, updateHitCounter2Display} from './display.js';
import { pongColors } from './pong_bind.js';


///////////////////////////////////grab mechanic//////////////////////////////////////
function grabBall(player) 
{
    ball.userData.heldBy = player;
	if (player === 1)
	{
		settings.player1HitCounter = 0;
		updatePaddleColor(1, 0x0aa23b);
	}
	else
	{
		settings.player2HitCounter = 0;
		updatePaddleColor(2, 0x0aa23b);
	}
	updateHitCounter1Display();
	updateHitCounter2Display();
}


///////////////////////////////////ball physics//////////////////////////////////////
function paddleCollision(closestIntersection, closestCube, potentialPosition)
{
    // Handle collision using your original angle-based rebound method
    const player = closestCube.position.x < 0 ? 1 : 2;
    const hitCounter = player === 1 ? settings.player1HitCounter : settings.player2HitCounter;

    if (hitCounter >= settings.superChargeCount) 
        grabBall(player);
    else 
    {
        // Increment hit counter
        if (player === 1 && settings.lastHit != 1) {
            settings.updatePlayer1HitCounter(settings.player1HitCounter + 1);
            settings.updateLastHit(1);
        } 
        else if (player === 2 && settings.lastHit != 2)
        {
            settings.updatePlayer2HitCounter(settings.player2HitCounter + 1);
            settings.updateLastHit(2);
        }
        updateHitCounter1Display();
        updateHitCounter2Display();

        let paddleMiddle;
        if (player === 1)
            paddleMiddle = settings.player1Positions[Math.floor(settings.lineLength / 2)].z;
        else
            paddleMiddle = settings.player2Positions[Math.floor(settings.lineLength / 2)].z;
        const paddleMiddleOnplane = paddleMiddle - ((settings.platformLength / 2) * settings.cubeSize);

        // Check if the collision is on the front face or top/bottom edges
        if (Math.abs(closestIntersection.z - paddleMiddleOnplane) < settings.lineLength / 2 + 0.2) 
        {
            // Front face collision - use angle-based rebound
            const maxAngle = 0.5;
            const angle = Math.max(maxAngle * -1, Math.min(maxAngle, ((potentialPosition.z - paddleMiddleOnplane) / (settings.lineLength / 2)) * maxAngle));

            settings.ballVelocity.z = angle;
            settings.ballVelocity.x *= -1;
        } 
        else 
        {
            settings.ballVelocity.z *= -1;
        }

        // Adjust ball position to prevent sticking to the position of the impact
        let positionOnPaddle = new THREE.Vector3(closestCube.position.x + (settings.ballVelocity.x > 0 ? 0.6: -0.6), 1, ball.position.z );
        ball.position.copy(positionOnPaddle);

        // Increase ball speed on collision with player
        settings.updateBallSpeed(settings.ballSpeed * settings.speedIncreaseFactor);
        settings.ballVelocity.normalize().multiplyScalar(settings.ballSpeed);
    }
}


export function updateBallPosition() 
{
    if (settings.gameMode === 'remote 1v1' || settings.gameStatus === 'paused')
        return;

    if (ball.userData.heldBy !== null)
    {
        // If the ball is held by a player, update its position to follow the paddle
        const playerPositions = ball.userData.heldBy === 1 ? settings.player1Positions : settings.player2Positions;
        const middlePos = playerPositions[Math.floor(settings.lineLength / 2)];
        ball.position.set(
            middlePos.x - settings.platformWidth / 2 + (ball.userData.heldBy === 1 ? 2 : -1),
            1,
            middlePos.z - settings.platformLength / 2
        )
        return;
    }

    // Calculate potential new position (only in XZ plane)
    const potentialPosition = ball.position.clone().add(new THREE.Vector3(settings.ballVelocity.x, 0, settings.ballVelocity.z));

    // Create a ray for collision detection (only in XZ plane)
    const rayDirection = new THREE.Vector3(settings.ballVelocity.x, -0.3, settings.ballVelocity.z).normalize();
    // ray that check left and right from the main ray
    const rayDirectionLeft = new THREE.Vector3(settings.ballVelocity.x, -0.3, settings.ballVelocity.z - 0.5).normalize();
    const rayDirectionRight = new THREE.Vector3(settings.ballVelocity.x, -0.3, settings.ballVelocity.z + 0.5).normalize();
    const ray = new THREE.Ray(ball.position, rayDirection);
    const rayLeft = new THREE.Ray(ball.position, rayDirectionLeft);
    const rayRight = new THREE.Ray(ball.position, rayDirectionRight);
    const rayLength = 0.5;

    // Check for collisions with raised cubes
    let collision = false;
    let closestIntersection = null;
    let closestCube = null;

    settings.cubes.forEach(cube => {
        const playerColor = cube.position.x < 0 ? pongColors.player1Paddle : pongColors.player2Paddle;
        if (cube.material.color.getHex() === playerColor || cube.material.color.getHex() === 0x0aa23b) {
            const cubeBoundingBox = new THREE.Box3().setFromObject(cube);
            const intersection = ray.intersectBox(cubeBoundingBox, new THREE.Vector3());
            const intersectionLeft = rayLeft.intersectBox(cubeBoundingBox, new THREE.Vector3());
            const intersectionRight = rayRight.intersectBox(cubeBoundingBox, new THREE.Vector3());


            if (intersection && intersection.distanceTo(ball.position) <= rayLength) {
                if (!closestIntersection || intersection.distanceTo(ball.position) < closestIntersection.distanceTo(ball.position)) {
                    closestIntersection = intersection;
                    closestCube = cube;
                    collision = true;
                }
            }
            else if (intersectionLeft && intersectionLeft.distanceTo(ball.position) <= rayLength + 0.05) {
                if (!closestIntersection || intersectionLeft.distanceTo(ball.position) < closestIntersection.distanceTo(ball.position)) {
                    closestIntersection = intersectionLeft;
                    closestCube = cube;
                    collision = true;
                }
            }
            else if (intersectionRight && intersectionRight.distanceTo(ball.position) <= rayLength + 0.05) {
                if (!closestIntersection || intersectionRight.distanceTo(ball.position) < closestIntersection.distanceTo(ball.position)) {
                    closestIntersection = intersectionRight;
                    closestCube = cube;
                    collision = true;
                }
            }
        }
    });

    if (collision) {
        paddleCollision(closestIntersection, closestCube, potentialPosition);
    } 
    else 
    {
        // Update ball position if no collision occurred
        ball.position.copy(potentialPosition);
    }

    // Make ball bounce on walls
    if (ball.position.z < -settings.platformLength / 2 + 0.5 || ball.position.z > settings.platformLength / 2 - 0.5) {
        settings.ballVelocity.z *= -1;
        ball.position.z = Math.max(Math.min(ball.position.z, settings.platformLength / 2 - 0.5), -settings.platformLength / 2 + 0.5);
    }

    // Check if ball is behind player lines
    if (ball.position.x < -settings.platformWidth / 2 - 1) //left side
    {
        settings.updatePlayer2Score(settings.player2Score + 1);
        updateScoreDisplay();
        settings.updateServSide(1);
        if (settings.player2Score >= settings.maxScore)
            quit();
        resetBall();

    }
    else if (ball.position.x > settings.platformWidth / 2 + 1) //right side
    {
        settings.updatePlayer1Score(settings.player1Score + 1);
        updateScoreDisplay();
        settings.updateServSide(2);
        if (settings.player1Score >= settings.maxScore)
            quit();
        resetBall();
    }
}
