/////////////////////////////////Environment settings/////////////////////////////////
export class Settings {
    constructor() {
        /////////////////////////////////3D environment settings//////////////////////////////
        this.scene = new THREE.Scene();
        this.camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        this.rendererSettings = {
            antialias: true,
            alpha: true,
            powerPreference: "high-performance"
        };
        this.renderer = new THREE.WebGLRenderer(this.rendererSettings);
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        document.body.appendChild(this.renderer.domElement);


        const rgbeLoader = new THREE.RGBELoader();
        rgbeLoader.load('../texture/royal_esplanade_4k.hdr', ( texture ) => {

            texture.mapping = THREE.EquirectangularReflectionMapping;

            this.scene.background = texture;
            this.scene.environment = texture;

        } );

        ///////////////////////////////////game settings//////////////////////////////////////
        this.lineLength = 5; // Paddle length
        this.targetHeight = 0.6; // Lift height for the cubes
        this.liftSpeed = 0.1; // Speed of the cubes lift
        this.moveSpeed = 0.3; // Speed of the paddles
        this.initialBallSpeed = 1; // Initial speed of the ball
        this.ballSizeScale = 2; // Ball size
        this.speedIncreaseFactor = 1; // Speed increase factor after each hit
        this.superChargeCount = 5; // Number of hits to supercharge the ball
        this.platformWidth = 50; // Width of the platform
        this.platformLength = 30; // Length of the platform
        this.cubeSize = 1; // Size of the cubes
        this.cubes = [];

        ///////////////////////////////////useful variables///////////////////////////////////
        this.ballSpeed = this.initialBallSpeed;
        this.ballVelocity = new THREE.Vector3(this.ballSpeed, 0, this.ballSpeed);
        this.player1Score = 0;
        this.player2Score = 0;
        this.maxScore = 15; // Max score to win the game
        this.player1HitCounter = 0; // Number of hits by player 1 for supercharge
        this.player2HitCounter = 0; // Number of hits by player 2 for supercharge
        this.ServSide = 2; // Wich player will serve
        this.lastHit = 1; // Last player to hit the ball
        this.gameStatus = 'paused';
        this.displayStatus = 'start';
        this.remoteRole = 'none';
        this.gameMode = 'local 1v1';
		this.gameStartTime = Date.now();
        this.player1UpBind = 'w';
        this.player1DownBind = 's';
        this.player2UpBind = 'ArrowUp';
        this.player2DownBind = 'ArrowDown';

        ///////////////////////////////////paddle settings////////////////////////////////////
        this.centerZ = this.lineLength === this.platformLength ? 0 : Math.floor((this.platformLength - this.lineLength) / 2);
        this.player1Positions = Array(this.lineLength).fill().map((_, index) => ({ x: 0, z: this.centerZ + index }));
        this.player2Positions = Array(this.lineLength).fill().map((_, index) => ({ x: this.platformWidth - 1, z: this.centerZ + index }));

        ///////////////////////////////////visual settings////////////////////////////////////
        this.camera.position.y = 2.7;
        this.camera.position.z = 22.75;
        this.camera.rotation.x = -0.97;
        this.camera.lookAt(0, this.camera.position.y, 6);

        const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
        this.scene.add(ambientLight);
        this.directionalLight = new THREE.DirectionalLight(0xffffff, 1);
        this.directionalLight.position.set(5, 3, 23.5);
        this.scene.add(this.directionalLight);
    }
    destroy() {
        // Remove all children from the scene and dispose of them
        while (this.scene.children.length > 0) {
            const child = this.scene.children[0];
            this.scene.remove(child);
    
            if (child.geometry) {
                child.geometry.dispose();
            }
    
            if (child.material) {
                // If the material is an array (e.g., multi-material objects)
                if (Array.isArray(child.material)) {
                    child.material.forEach((material) => material.dispose());
                } else {
                    child.material.dispose();
                }
            }
    
            if (child.texture) {
                child.texture.dispose();
            }
        }
    
        // Dispose of the renderer
        this.renderer.dispose();
    
        // Remove the renderer's DOM element
        if (this.renderer.domElement && this.renderer.domElement.parentNode) {
            this.renderer.domElement.parentNode.removeChild(this.renderer.domElement);
        }
    
        // Optionally, clear textures or background
        if (this.scene.background && this.scene.background.dispose) {
            this.scene.background.dispose();
        }
        if (this.scene.environment && this.scene.environment.dispose) {
            this.scene.environment.dispose();
        }
    
        // Reset variables if necessary
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.cubes = [];
        this.ballVelocity = null;
    
        // Remove event listeners
        window.removeEventListener('resize', this.onResize);
    }

    ///////////////////////////////////update functions////////////////////////////////////
    updateBallSpeed(newValue) { this.ballSpeed = newValue; }
    updateBallVelocity(newValue) { this.ballVelocity = newValue; }
    updatePlayer1Score(newValue) { this.player1Score = newValue; }
    updatePlayer2Score(newValue) { this.player2Score = newValue; }
    updatePlayer1HitCounter(newValue) { this.player1HitCounter = newValue; }
    updatePlayer2HitCounter(newValue) { this.player2HitCounter = newValue; }
    updateServSide(newValue) { this.ServSide = newValue; }
    updateLastHit(newValue) { this.lastHit = newValue; }
    updateGameStatus(newValue) { this.gameStatus = newValue; }
    updatePlayer1Positions(newValue) { this.player1Positions = newValue; }
    updatePlayer2Positions(newValue) { this.player2Positions = newValue; }
    updateDirectionalLight(position) { this.directionalLight.position.set(position.x, position.y, position.z); }
    updateDirectionalLightSmoothly(position) {
        gsap.to(this.directionalLight.position, {
            duration: 2,
            x: position.x,
            y: position.y,
            z: position.z,
            ease: "power2.inOut"
        });
    }
    updateTime() { this.gameStartTime = Date.now(); }
    updateBindKeys(player1Up, player1Down, player2Up, player2Down) {
        this.player1UpBind = player1Up;
        this.player1DownBind = player1Down;
        this.player2UpBind = player2Up;
        this.player2DownBind = player2Down;
    }
}
