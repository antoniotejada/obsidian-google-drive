// Debuglevels in increasing severity so messages >= indexOf(debugLevel) will be
// shown
export const DEBUG_LEVELS = ["debug", "info", "warn", "error"];

export let logError = function(message?: any, ...optionalParams: any[]) {};
export let logWarn = function(message?: any, ...optionalParams: any[]) {};
// Note console.log is an alias of console.info
export let logInfo = function(message?: any, ...optionalParams: any[]) {};
export let logDbg = function(message?: any, ...optionalParams: any[]) {};

export function hookLogFunctions(debugLevelIndex: number, tag: string) {
    logInfo("hookLogFunctions", debugLevelIndex, tag);

    const logIgnore = function(message?: any, ...optionalParams: any[]) {};
    logError = (debugLevelIndex <= DEBUG_LEVELS.indexOf("error")) ?
        console.error.bind(console, tag + "[ERROR]:") :
        logIgnore;
    logWarn = (debugLevelIndex <= DEBUG_LEVELS.indexOf("warn")) ?
        console.warn.bind(console, tag + "[WARN]:") :
        logIgnore;
    logInfo = (debugLevelIndex <= DEBUG_LEVELS.indexOf("info")) ?
        console.info.bind(console, tag + "[INFO]:") :
        logIgnore;
    logDbg = (debugLevelIndex <= DEBUG_LEVELS.indexOf("debug")) ?
        console.debug.bind(console, tag + "[DEBUG]:") :
        logIgnore;
}

function debugbreak() {
    debugger;
}
