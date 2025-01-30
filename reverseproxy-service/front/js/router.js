// Double click handler
const lastClickTimes = new Map();
const DOUBLE_CLICK_DELAY = 300;

// Keep track of scripts and modules for different routes
const routeScripts = new Map();
const routeModules = new Map();
const routeScriptListeners = new Map();

const cleanupRouteScript = async (path) => {
    const script = routeScripts.get(path);
    const module = routeModules.get(path);
    const scriptListeners = routeScriptListeners.get(path);

    // If the route has a custom cleanup function, call it
    if (module && typeof module.quit === 'function') {
        await module.quit();
    }

    // Remove any specific event listeners
    if (scriptListeners) {
        scriptListeners.forEach(({ element, event, listener }) => {
            element.removeEventListener(event, listener);
        });
    }

    // Remove the script
    if (script) {
        script.remove();
        routeScripts.delete(path);
    }

    // Clear the module
    if (module) {
        routeModules.delete(path);
    }

    // Clear listeners
    routeScriptListeners.delete(path);
};

function handleTabs() {
    const tabButtons = document.querySelectorAll('[role="tab"]');
    const tabPanels = document.querySelectorAll('[role="tabpanel"]');
    
    function switchTab(event) {
        tabButtons.forEach(button => {
            button.setAttribute('aria-selected', 'false');
        });
        tabPanels.forEach(panel => {
            panel.hidden = true;
        });
        const clickedTab = event.target;
        clickedTab.setAttribute('aria-selected', 'true');
        const tabPanelId = clickedTab.getAttribute('aria-controls');
        const tabPanel = document.getElementById(tabPanelId);
        tabPanel.hidden = false;
    }
    
    tabButtons.forEach(button => {
        button.addEventListener('click', switchTab);
    });
}

const attachRouteScriptListeners = async (path, module) => {
    if (path === '/pong') {
        const startButton = document.getElementById('startButton');
        if (startButton && module && typeof module.initializeGame === 'function') {
            const listener = () => module.initializeGame();
            startButton.addEventListener('click', listener);
            
            // Store the listener for potential cleanup
            const currentListeners = routeScriptListeners.get(path) || [];
            routeScriptListeners.set(path, [
                ...currentListeners, 
                { element: startButton, event: 'click', listener }
            ]);
        }
    }
    if (path === '/settings' || path === '/about') {
        handleTabs();
    }
};

const loadRouteModule = async (path) => {
    try {
        // Dynamically map routes to their corresponding JS modules
        const routeModulePaths = {
            '/pong': '../js/pong/main.js',
            '/about': '../js/page_script/tabs.js',
            '/profile': '../js/page_script/profile.js',
            '/': '../js/page_script/home.js',
        };

        const modulePath = routeModulePaths[path];
        if (!modulePath) return null;

        const module = await import(modulePath);
        routeModules.set(path, module);
        return module;
    } catch (error) {
        console.error(`Error loading module for route ${path}:`, error);
        return null;
    }
};

const insertRouteScript = async (path) => {
    const routeScriptPaths = {
        '/pong': '../js/pong/main.js',
        '/about': '../js/page_script/tabs.js',
        '/profile': '../js/page_script/profile.js',
        '/': '../js/page_script/home.js',
    };

    const scriptPath = routeScriptPaths[path];
    if (!scriptPath) return;

    // Remove the old script if it exists
    const oldScript = routeScripts.get(path);
    if (oldScript) {
        oldScript.remove();
        routeScripts.delete(path);
    }

    // Create and append the new script
    const script = document.createElement('script');
    script.src = `${scriptPath}?v=${Date.now()}`; // Cache-busting
    script.type = 'module';
    routeScripts.set(path, script);
    document.getElementById("main-page").appendChild(script);


    // Load the corresponding module
    const module = await loadRouteModule(path);
    
    // Attach any route-specific script listeners
    if (module) {
        await attachRouteScriptListeners(path, module);
    }
};

// Double click handler
export const route = (event = null, forcedPath = null) => {
    event = event || window.event;
    if (event) {
        event.preventDefault();
    }

    let path = forcedPath;
    let link = null;

    if (!path) {
        link = event?.target.closest('a');
        if (link) {
            path = link.href;
        }
    }

    if (path && link) {
        const currentTime = new Date().getTime();
        const lastClickTime = lastClickTimes.get(path) || 0;
        
        if (currentTime - lastClickTime <= DOUBLE_CLICK_DELAY) {
            window.history.pushState({}, "", path);
            handleLocation();
            lastClickTimes.delete(path);
        } else {
            lastClickTimes.set(path, currentTime);
        }
    } else if (forcedPath) {
        window.history.pushState({}, "", path);
        handleLocation();
    }
};

const routes = {
    404: "/html/404.html",
    "/": "/html/home.html",
    "/settings": "/html/settings.html",
    "/profile": "/html/profile.html",
    "/pong": "/html/pong.html",
    "/about": "/html/about.html",
    "/chat": "/html/chat.html"
};

const handleLocation = async () => {
    const path = window.location.pathname;
    
    // Cleanup any previous route-specific scripts
    for (let [routePath] of routeScripts) {
        if (routePath !== path) {
            await cleanupRouteScript(routePath);
        }
    }
    
    const route = routes[path] || routes[404];
    const html = await fetch(route).then((data) => data.text());
    
    // Insert HTML for the route
    if (path === '/'){
        document.body.style.backgroundImage = "url('../../texture/backSefir.jpeg')";
        // Create a temporary DOM element to parse the HTML
        const tempDiv = document.createElement("div");
        tempDiv.innerHTML = html;

        // Extract only the content inside #main-page
        const mainPageContent = tempDiv.querySelector("#main-page")?.innerHTML || "";

        // Set it to the main-page element
        document.getElementById("main-page").innerHTML = mainPageContent;
    }
    else {
        document.body.style.backgroundImage = "url('../../texture/backColor.jpg')";
        document.getElementById("main-page").innerHTML = html;
    }
    
    // Load route-specific script if applicable
    await insertRouteScript(path);
    
    // Update navbar visibility
    document.body.setAttribute('data-show-navbar', path === '/');
};

window.onpopstate = handleLocation;
window.route = route;
handleLocation();