///////////////////////////////////////imports////////////////////////////////////////
import { ball, initBall } from "./ball_init.js";
import { resetBall, sleep } from "./resetBall.js";
import { initMiddlePlatform, initSides } from "./roundedBox.js";
import { updateCubeSelection, updatePlayerPositions, movePlayerRemote, pressedKeys } from "./movements.js";
import { updateBallPosition } from "./ball_physics.js";
import { updateScoreDisplay, updateClock, initScoreboard, initClock} from "./display.js";
import { focusGame, initMonitor, focusMonitor, initTable} from "./monitor.js";
import { onKeyDown, onKeyUp, onMouseWheel } from "./keyEvents.js";
import { Settings } from "./settings.js";
import { titleDisplay } from "./monitor_display.js";
import { buildFriendList } from "../page_script/friendList.js";
import { pongBindings, pongColors, pongSet, getMatchWinners } from "./pong_bind.js";

// ///////////////////////////////////environment settings///////////////////////////////
export let settings = null;

let currentRemoteGame = null;
///////////////////////////////////main functions/////////////////////////////////////

function advance(player) {
    const matchWinners = getMatchWinners();

    if (pongSet.current_match === 1) {
        pongSet.players_names[4] = pongSet.players_names[player];
        matchWinners.semifinal1Winner.value = pongSet.players_names[player];
    }
    else if (pongSet.current_match === 2) {
        pongSet.players_names[5] = pongSet.players_names[player];
        matchWinners.semifinal2Winner.value = pongSet.players_names[player];
    }
    else {
        pongSet.players_names[6] = pongSet.players_names[player];
        matchWinners.finalWinner.value = pongSet.players_names[player];
    }
}

function annonceWinner(player1, player2) {
    if (settings.player1Score > settings.player2Score) {
        alert(pongSet.players_names[player1] + ' wins the match!');
        advance(player1);
    }
    else {
        alert(pongSet.players_names[player2] + ' wins the match!');
        advance(player2);
    }
}

export async function quit() {
    if (settings) {
        if (settings.player1Score === settings.maxScore || settings.player2Score === settings.maxScore) {
            if (settings.gameMode === 'local tournament' ) {
                if (pongSet.current_match === 1) {
                    annonceWinner(0, 1);
                    pongSet.current_match++;
                }
                else if (pongSet.current_match === 2) {
                    annonceWinner(2, 3);
                    pongSet.current_match++;
                }
                else {
                    annonceWinner(4, 5);
                    alert(pongSet.players_names[6] + ' wins the tournament!');
                    pongSet.current_match = 1;
                }
            }
            else {
                if (settings.player1Score > settings.player2Score)
                    alert(pongSet.players_names[0] + ' wins the match!');
                else
                    alert(pongSet.players_names[1] + ' wins the match!');
            }  
        }
    }

    if (settings) {
        focusMonitor();
        await sleep(2000);

        if (settings) {
            settings.destroy();
            settings = null;
        }
    }

    if (window.pongSocket) {
        console.log("window.pongSocket before close: ", window.pongSocket);
        window.pongSocket.close();
        window.pongSocket = null;
    }

    document.getElementById('nav').style.display = 'block';
    document.getElementById('Taskbar').style.display = 'flex';
    document.getElementById('startButton').style.display = 'block';
    document.getElementById('titleBarPong').style.display = 'flex';
    document.getElementById('leftWindow').style.display = 'flex';
    document.getElementById('rightWindow').style.display = 'flex';

    //stop event listeners
    window.removeEventListener('keydown', onKeyDown, false);
    window.removeEventListener('keyup', onKeyUp, false);
    window.removeEventListener('wheel', onMouseWheel, false);
    //stop animation loop
    window.cancelAnimationFrame(animate);
}

// Animation loop
function animate() {
    if (settings)
    {
        requestAnimationFrame(animate);

        updatePlayerPositions();
        updateCubeSelection();
        updateBallPosition();

        // Raise/lower cubes animation
        settings.cubes.forEach(cube => {
            if (cube.userData.targetY !== undefined) {
                cube.position.y += (cube.userData.targetY - cube.position.y) * settings.liftSpeed;
            }
        });

        settings.renderer.render(settings.scene, settings.camera);
    }
}

async function resetGame() {
    if (!settings) 
        return;
    settings.player1Score = 0;
    settings.player2Score = 0;
    updateScoreDisplay();
    await sleep(1500);
    if (settings.gameStatus === 'started') {
        resetBall();
    }
}

function initEnvironment() {
    if (!settings) return;
    getPlayersNames();
    initSides();
    initMiddlePlatform();
    initScoreboard();
    initClock();
}

export async function startGame(gameId) {
    if (!settings) return;
    // settings.
    if (settings.gameMode === 'remote 1v1') {
        remote_game(gameId);
    }
    else
        updateClock();
    initBall();
    resetGame();
}

export async function remote_game(gameId) {
    const accessToken = sessionStorage.getItem('accessToken');
    if (accessToken) {
        
		const encodedToken = encodeURIComponent(accessToken);
        window.pongSocket = new WebSocket(`wss://${window.location.host}/remote/${gameId}/?${encodedToken}`);
        window.pongSocket.onopen = function () {
            console.log('pong WebSocket connection established');
        };
        window.pongSocket.onerror = function (error) {
            console.error('pong WebSocket error:', error);
        };
        window.pongSocket.onclose = function () {
            console.log('pong WebSocket connection closed');
            quit();
        };

        window.pongSocket.onmessage = function (event) {
            const message = JSON.parse(event.data);
            // console.log('Received message:', message);
            if (message.event === 'assign_role') {
                settings.remoteRole = message.data;
                // console.log('Assigned role:', settings.remoteRole);
            }
            if (message.event === 'game_update') {
                // console.log(`Ball position: ${ball.position.x}, ${ball.position.z}`);
                ball.position.x = message.data.ball.x;
                ball.position.z = -message.data.ball.y;

                // console.log(`centerZ: ${settings.centerZ}`);
                // console.log(`Player 1 positions: `, message.data.players.left.pos.y);
                // console.log(`Player 2 positions: `, message.data.players.right.pos.y);
                // settings.updatePlayer1Positions(movePlayerRemote(settings.player1Positions, settings.centerZ - message.data.players.left.pos.y + 2));
                // settings.updatePlayer2Positions(movePlayerRemote(settings.player2Positions, settings.centerZ - message.data.players.right.pos.y + 2));
                settings.updatePlayer1Positions(movePlayerRemote(settings.player1Positions, 15 - message.data.players.left.pos.y));
                settings.updatePlayer2Positions(movePlayerRemote(settings.player2Positions, 15 - message.data.players.right.pos.y));


                if (settings.player1Score !== message.data.players.left.score || settings.player2Score !== message.data.players.right.score) {

                    settings.updatePlayer1Score(message.data.players.left.score);
                    settings.updatePlayer2Score(message.data.players.right.score);
                    updateScoreDisplay();
                    settings.updateServSide(1);
                    if (settings.player2Score >= settings.maxScore || settings.player1Score >= settings.maxScore)
                        quit();
                    resetBall();
                }

            }
            if (message.event === 'start_game') {
                settings.gameStatus = 'started';
                settings.updateTime();
                updateClock();
                console.log('Game started');
            }
            if (message.event === 'game_ended') {
                settings.gameStatus = 'finished';
                currentRemoteGame = null;
                console.log('Game ended');
            }
        };
    }
}

window.addEventListener('blur', function () {
    if (pressedKeys)
        for (let key in pressedKeys)
            pressedKeys[key] = false;
    });

function progressLoading() {
    //create a progress bar and puttin it in the middle of the screen
    const progressBar = document.createElement('progress');
    progressBar.value = 0;
    progressBar.style.position = 'absolute';
    progressBar.style.left = '50%';
    progressBar.style.top = '50%';
    progressBar.style.width = '200px';
    progressBar.style.height = '20px';
    progressBar.style.transform = 'translate(-50%, -50%)';
    progressBar.style.zIndex = '1000';
    document.body.appendChild(progressBar);

    //loading progress over 5 seconds
    let progress = 0;
    const interval = setInterval(() => {
        progress += 0.1;
        progressBar.value = progress;
        if (progress >= 50) {
            clearInterval(interval);
            progressBar.remove();
        }
    }, 300);

    //remove the progress bar after 5 seconds
    setTimeout(() => {
        progressBar.remove();
    }, 3000);
}

function changePlayStyle()
{
    if (settings.gameMode !== 'local 1v1')
        return;

    // Get the currently checked play style
    const checkedRadio = document.querySelector('input[name="fieldset-example"]:checked');

    if (!checkedRadio) {
        console.log("No play style button is checked.");
    } 
    else {
        const label = document.querySelector(`label[for="${checkedRadio.id}"]`);
        const playStyle = label.textContent.toLowerCase();
        if (playStyle === 'slow') {
            settings.initialBallSpeed = 0.3
        }
        
        else if (playStyle === 'normal') {
            settings.initialBallSpeed = 0.5
        }

        else if (playStyle === 'fast') {
            settings.initialBallSpeed = 1;
        }

        else if (playStyle === 'super fast') {
            settings.initialBallSpeed = 1.3;
        }

        else if (playStyle === 'butterfly') {
            settings.initialBallSpeed = 0.3;
            settings.speedIncreaseFactor = 1.3;
        }

    }
}

export async function initializeGame(gameId) {
    console.log('Initializing game...');
    console.log('Players in the game: ', pongSet.players_names);
    document.getElementById('waitingScreen').style.display = 'block';
    document.getElementById('nav').style.display = 'none';
    document.getElementById('startButton').style.display = 'none';
    document.getElementById('leftWindow').style.display = 'none';
    document.getElementById('rightWindow').style.display = 'none';
    progressLoading();
    window.addEventListener('keydown', onKeyDown, false);
    window.addEventListener('keyup', onKeyUp, false);
    window.addEventListener('wheel', onMouseWheel, false);
    settings = new Settings();
    settings.gameMode = pongSet.selectedMode;
    if (gameId) {
        currentRemoteGame = gameId;
        settings.gameMode = 'remote 1v1';
    }
    settings.updateBindKeys(pongBindings.player1UpBind, pongBindings.player1DownBind, pongBindings.player2UpBind, pongBindings.player2DownBind);
    changePlayStyle();
    initMonitor();
    initTable();
    titleDisplay();
    await sleep(3000);
    settings.updateTime();
    animate();
    initEnvironment();
    startGame(gameId);
    document.getElementById('Taskbar').style.display = 'none';
    document.getElementById('titleBarPong').style.display = 'none';
    document.getElementById('waitingScreen').style.display = 'none';
    focusGame();
    await sleep(3000);
    settings.updateGameStatus('started');
}

////////////////////////////////////////////////////////Page script////////////////////////////////////////////////////////
//////////////////////////////////////Window Swap//////////////////////////////////////
function setupGameModeSelect() {
    const gameModeSelect = document.getElementById('gameModeSelect');
    const sections = {
        "local 1v1": document.querySelector('.local1v1'),
        "local tournament": document.querySelector('.localTournament'),
        "remote 1v1": document.querySelector('.remote1v1'),
    };
    if (gameModeSelect) {
        gameModeSelect.addEventListener('change', function () {
            pongSet.selectedMode = gameModeSelect.value.toLowerCase();
            // console.log('sections: ', sections);
            // gameModeSelect = selectedMode;
            // Hide all sections
            Object.values(sections).forEach(section => {
                if (section) {
                    section.style.display = 'none';
                }
            });

            // Show the selected section
            if (sections[pongSet.selectedMode]) {
                sections[pongSet.selectedMode].style.display = 'flex';
            }
            const fieldRows = document.querySelectorAll('.field-row');
            
            if (pongSet.selectedMode === 'remote 1v1') {
                buildFriendList(sessionStorage.getItem('accessToken'), 'friendList', null);
                fieldRows.forEach(fieldRow => fieldRow.style.visibility = 'hidden');
            }
            else if (fieldRows[0].style.visibility === 'hidden')
                fieldRows.forEach(fieldRow => fieldRow.style.visibility = 'visible');
        });
    }
}


//////////////////////////////////////Player Names//////////////////////////////////////
function getPlayersNames() {
    if (settings.gameMode === 'local tournament') {
        const playerInputs = document.querySelectorAll('.player-input');
        playerInputs.forEach((input, index) => {
            // Immediately capture current input value
            if (input.value)
                pongSet.players_names[index] = input.value;
            
            // Add input event listener for future changes
            input.addEventListener('input', () => {
                pongSet.players_names[index] = input.value || null;
            });
        });
    }
}

//////////////////////////////////////Game Settings//////////////////////////////////////
if (window.location.pathname === '/pong') {
    // Handle color picker updates
    function updateColor(buttonId, colorDisplayId) {
        if (!document.getElementById(buttonId))
            return;
        const button = document.getElementById(buttonId);
        const colorDisplay = document.getElementById(colorDisplayId);

        button.addEventListener("click", () => {
            const colorInput = document.createElement("input");
            colorInput.type = "color";
            colorInput.style.display = "none";

            document.body.appendChild(colorInput);
            colorInput.click();

            colorInput.addEventListener("input", () => {
                colorDisplay.style.backgroundColor = colorInput.value;
                
                // Convert hex color to 0x format and update the corresponding variable
                const colorValue = parseInt(colorInput.value.replace('#', '0x'));
                
                switch(buttonId) {
                    case 'player1SideColorBtn':
                        pongColors.player1Side = colorValue;
                        break;
                    case 'player1PaddleColorBtn':
                        pongColors.player1Paddle = colorValue;
                        break;
                    case 'player2SideColorBtn':
                        pongColors.player2Side = colorValue;
                        break;
                    case 'player2PaddleColorBtn':
                        pongColors.player2Paddle = colorValue;
                        break;
                }

            });

            colorInput.addEventListener("change", () => {
                document.body.removeChild(colorInput);
            });
        });
    }

    // Handle keybinding updates
    function updateKeybind(buttonId, keyDisplayId, action, buttonDefaultText) {
        const button = document.getElementById(buttonId);
        if (!document.querySelector(`#${keyDisplayId} kbd`))
            return;
        const keyDisplay = document.querySelector(`#${keyDisplayId} kbd`);

        // Set default key display
        keyDisplay.innerText = getKeyDisplay(keyBindings[action]);

        button.addEventListener("click", () => {
            button.innerText = "Press a key...";

            const onKeyPress = (event) => {
                event.preventDefault(); // Prevent default browser actions
                const key = event.key; // Keep original key case
                const upperKey = key.toUpperCase(); // Uppercase version for tracking

                // Check if key is already assigned to another action
                if (assignedKeys.has(upperKey) && keyBindings[action].toUpperCase() !== upperKey) {
                    alert(`The key "${getKeyDisplay(key)}" is already assigned to another action. Please choose a different key.`);
                    button.innerText = buttonDefaultText;
                    document.removeEventListener("keydown", onKeyPress);
                    return;
                }

                // Update bindings
                const oldKey = keyBindings[action].toUpperCase();
                assignedKeys.delete(oldKey); // Remove old key from the set
                keyBindings[action] = upperKey;
                assignedKeys.add(upperKey); // Add new key to the set

                keyDisplay.innerText = getKeyDisplay(key);
                button.innerText = buttonDefaultText;
                document.removeEventListener("keydown", onKeyPress);

                // Update the keybindings for the game
                // Preserve the original case for special keys like 'ArrowUp'
                let bindingKey = key;
                if (key.startsWith('Arrow')) {
                    bindingKey = key; // Keep original case for arrow keys
                } else {
                    bindingKey = key.toLowerCase(); // Use lowercase for regular keys
                }

                // Update the game bindings
                if (action === 'player1Up') {
                    pongBindings.player1UpBind = bindingKey;
                } else if (action === 'player1Down') {
                    pongBindings.player1DownBind = bindingKey;
                } else if (action === 'player2Up') {
                    pongBindings.player2UpBind = bindingKey;
                } else if (action === 'player2Down') {
                    pongBindings.player2DownBind = bindingKey;
                }

            };

            document.addEventListener("keydown", onKeyPress);
        });
    }

    const assignedKeys = new Set();
    const keyBindings = {
        player1Up: pongBindings.player1UpBind,
        player1Down: pongBindings.player1DownBind,
        player2Up: pongBindings.player2UpBind,
        player2Down: pongBindings.player2DownBind
    };

    // Key display mapping
    const keyDisplayMapping = {
        ArrowUp: "↑",
        ArrowDown: "↓",
        ArrowLeft: "←",
        ArrowRight: "→",
        ARROWUP: "↑",
        ARROWDOWN: "↓",
        ARROWLEFT: "←",
        ARROWRIGHT: "→",
        " ": "Space",
        Enter: "Enter",
        Backspace: "Backspace"
    };

    // Function to reset assigned keys based on current bindings
    function resetAssignedKeys() {
        assignedKeys.clear();
        Object.values(keyBindings).forEach(key => assignedKeys.add(key.toUpperCase()));
    }

    // Function to get display value for a key
    function getKeyDisplay(key) {
        return keyDisplayMapping[key] || key.toUpperCase();
    }

    function setupKeyBindings() {
        // Initialize assignedKeys with default keys on page load
        resetAssignedKeys();

        // Initialize the functionality for both players
        updateKeybind("player1InputUp", "player1KeyUp", "player1Up", "Move Up");
        updateKeybind("player1InputDown", "player1KeyDown", "player1Down", "Move Down");
        updateKeybind("player2InputUp", "player2KeyUp", "player2Up", "Move Up");
        updateKeybind("player2InputDown", "player2KeyDown", "player2Down", "Move Down");

        updateColor("player1SideColorBtn", "player1SideColor");
        updateColor("player1PaddleColorBtn", "player1PaddleColor");
        updateColor("player2SideColorBtn", "player2SideColor");
        updateColor("player2PaddleColorBtn", "player2PaddleColor");
    }

    setupGameModeSelect();
    setupKeyBindings();
}
