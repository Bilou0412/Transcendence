// Configuration constants
const ROUTES = {
    404: "/html/404.html",
    "/": "/html/index.html",
    "/settings": "/html/settings.html",
    "/profile": "/html/profile.html",
    "/pong": "/html/pong.html",
    "/about": "/html/about.html",
    "/chat": "/html/chat.html"
};

const ROUTE_MODULE_PATHS = {
    '/pong': '../js/pong/main.js',
    '/about': '../js/page_script/tabs.js'
};

const DOUBLE_CLICK_DELAY = 300;

// State management for routes
const state = {
    lastClickTimes: new Map(),
    routeScripts: new Map(),
    routeModules: new Map(),
    routeScriptListeners: new Map()
};

// Utility function to handle tab switching
function handleTabs() {
    const tabButtons = document.querySelectorAll('[role="tab"]');
    const tabPanels = document.querySelectorAll('[role="tabpanel"]');
    
    const switchTab = (event) => {
        tabButtons.forEach(button => button.setAttribute('aria-selected', 'false'));
        tabPanels.forEach(panel => panel.hidden = true);
        
        const clickedTab = event.target;
        clickedTab.setAttribute('aria-selected', 'true');
        
        const tabPanelId = clickedTab.getAttribute('aria-controls');
        document.getElementById(tabPanelId).hidden = false;
    };
    
    tabButtons.forEach(button => button.addEventListener('click', switchTab));
}

// Clean up route-specific resources
async function cleanupRouteScript(path) {
    const { routeScripts, routeModules, routeScriptListeners } = state;
    const script = routeScripts.get(path);
    const module = routeModules.get(path);
    const scriptListeners = routeScriptListeners.get(path);

    if (module?.quit) await module.quit();

    scriptListeners?.forEach(({ element, event, listener }) => {
        element.removeEventListener(event, listener);
    });

    if (script) {
        script.remove();
        routeScripts.delete(path);
    }

    if (module) routeModules.delete(path);
    routeScriptListeners.delete(path);
}

// Attach route-specific event listeners
async function attachRouteScriptListeners(path, module) {
    const { routeScriptListeners } = state;

    if (path === '/pong') {
        const startButton = document.getElementById('startButton');
        if (startButton && module?.initializeGame) {
            const listener = () => module.initializeGame();
            startButton.addEventListener('click', listener);
            
            const currentListeners = routeScriptListeners.get(path) || [];
            routeScriptListeners.set(path, [
                ...currentListeners, 
                { element: startButton, event: 'click', listener }
            ]);
        }
    }

    if (['/settings', '/about'].includes(path)) {
        handleTabs();
    }
}

// Dynamically load route-specific module
async function loadRouteModule(path) {
    try {
        const modulePath = ROUTE_MODULE_PATHS[path];
        if (!modulePath) return null;

        const module = await import(modulePath);
        state.routeModules.set(path, module);
        return module;
    } catch (error) {
        console.error(`Route module load error: ${path}`, error);
        return null;
    }
}

// Insert route-specific script
async function insertRouteScript(path) {
    const scriptPath = ROUTE_MODULE_PATHS[path];
    if (!scriptPath) return;

    const script = document.createElement('script');
    script.src = scriptPath;
    script.type = 'module';
    state.routeScripts.set(path, script);
    document.getElementById("main-page").appendChild(script);

    const module = await loadRouteModule(path);
    if (module) await attachRouteScriptListeners(path, module);
}

// Handle route navigation
export const route = (event = null, forcedPath = null) => {
    event = event || window.event;
    event?.preventDefault();

    let path = forcedPath;
    let link = event?.target.closest('a');
    path = path || link?.href;

    if (path && link) {
        const currentTime = Date.now();
        const lastClickTime = state.lastClickTimes.get(path) || 0;
        
        if (currentTime - lastClickTime <= DOUBLE_CLICK_DELAY) {
            window.history.pushState({}, "", path);
            handleLocation();
            state.lastClickTimes.delete(path);
        } else {
            state.lastClickTimes.set(path, currentTime);
        }
    } else if (forcedPath) {
        window.history.pushState({}, "", path);
        handleLocation();
    }
};

// Primary location handler
async function handleLocation() {
    const path = window.location.pathname;
    
    // Cleanup previous route scripts
    for (let [routePath] of state.routeScripts) {
        if (routePath !== path) {
            await cleanupRouteScript(routePath);
        }
    }
    
    const route = ROUTES[path] || ROUTES[404];
    const html = await fetch(route).then((data) => data.text());
    
    const mainPageElement = document.getElementById("main-page");
    if (mainPageElement) {
        mainPageElement.innerHTML = html;
    } else {
        console.error('Element with id "main-page" not found.');
        return;
    }
    
    await insertRouteScript(path);
    
    document.body.setAttribute('data-show-navbar', path === '/');
}

window.onpopstate = handleLocation;
window.route = route;
handleLocation();