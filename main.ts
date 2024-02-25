/**
 * # Development notes
 *
 * ## Introduction
 *
 * https://developers.google.com/identity/protocols/oauth2
 * https://developers.google.com/workspace/guides/auth-overview
 * https://github.com/googleapis/google-auth-library-nodejs/blob/main/src/auth/oauth2client.ts#L127
 *
 * Oauth2 is the authorization mechanism used by google drive (and many others)
 *
 * - client id
 * - redirect uri: a global, localhost or oob (deprecated) uri
 * - client secret
 * - api key
 *
 * - PKCE: encode a challenge for both extra security but also in some
 *   implentations avoids having to send the client secret.
 *
 * ## Creating OAuth 2 credentials
 *
 * ### Create the project
 *
 * 1. Go to console at https://console.cloud.google.com/
 * 2. apis and services -> enabled apis and services
 * 3. create project
 *
 * ### Enable APIs and services
 * 1. Click on Enable APIs and services
 * 2. Choose Google Drive API -> Enable
 *
 * ### Create OAuth consent screen
 * 1. Click on OAuth consent screen
 * 2. Configure consent screen -> External
 * 3. Fill in app information, support contact information, developer contact
 *    information
 * 4. Add/remove scopes -> drive.file
 * 5. Add Test user (won't be able to be used until published or the user is
 *    part of test users).
 *
 * ### Create Credentials
 * 1. Create Credentials -> OAuth client ID
 * 2. Application type: Web Application
 * 3. Authorized redirect URIs: http://localhost
 * 4. Download JSON
 *
 * ## Quickstarts
 *
 * Using api libraries
 *
 * https://developers.google.com/identity/oauth2/web/guides/overview
 *
 * ## Authorization Flows
 *
 * https://accounts.google.com/o/oauth2/v2/auth
 *
 * ### Web server flow
 *
 * https://developers.google.com/identity/protocols/oauth2/web-server
 *
 * Requires a server to receive the oauth2 response.
 *
 * ### Client-side javascript flow (Implicit)
 *
 * https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow
 *
 * Instead of returning a code that needs to be exchanged for an access and a
 * refresh token this returns the token directly without the need for providing
 * the client secret

 * ### Mobile & Desktop app flow (native)
 *
 * #### Android
 * https://developers.google.com/identity/protocols/oauth2/native-app
 *
 * The registration requires
 * - ssh (can be made up)
 * - application package name in app.domain.com format (can be made up) No
 *   client secret
 *
 * ### OOB/ copy paste flow
 *
 * https://developers.google.com/identity/protocols/oauth2/resources/oob-migration
 *
 * Deprecated
 *
 * ### Loopback
 *
 * https://developers.google.com/identity/protocols/oauth2/resources/loopback-migration
 *
 * ### Limited device
 *
 * https://developers.google.com/identity/protocols/oauth2/limited-input-device
 *
 * Has scope restrictions, specifically google drive can only access drive.file
 * scope
 *
 * ### Service account
 *
 * https://developers.google.com/identity/protocols/oauth2/service-account
 *
 * ### Chrome identity api
 *
 * https://developer.chrome.com/docs/extensions/mv3/tut_oauth/
 *
 *
 * ## Oauth2 playground
 *
 * https://developers.google.com/oauthplayground/?
 *
 * ## Google drive api
 *
 *
 * https://www.googleapis.com/discovery/v1/apis/
 *
 * https://developers.google.com/drive/api/reference/rest/v3
 * https://developers.google.com/drive/api/guides/about-sdk
 * https://www.googleapis.com/discovery/v1/apis/drive/v3/rest
 *
 * ### Quickstarts
 *
 * https://developers.google.com/drive/api/quickstart/js
 * https://developers.google.com/drive/api/quickstart/nodejs
 * https://developers.google.com/drive/api/quickstart/python
 *
 * ### drive.files
 *
 * Requires sharing each file individually with or created by the app
 * Can list folders but will only return those shared with or created by the app
 * Gives 404 when trying to get 'root' name,parents
 *
 * https://developers.google.com/drive/api/guides/about-files
 * https://stackoverflow.com/questions/22403014/google-drive-api-scope-and-file-access-drive-vs-drive-files
 *
 * The benefit is that it works with OAuth device flow and that publishing the
 * app requires no verification
 *
 * ## Obsidian solutions
 *
 * ### Use api key
 *
 * ### Use client's api key
 *
 * ### Use oauth2 playground
 *
 * ### Loading client libraires
 *
 * Fails with CORS
 *
 * ### Open BrowserWindow, trap onBeforeRequest
 *
 * https://github.com/rdoering/evernote-migration-plugin/blob/master/main.ts#L143
 *
 * This is not available on mobile, needs to allow from desktop first and
 * transmit somehow to mobile
 *
 * ### Open the default browser, manual copy of the url
 *
 * ## References
 *
 * https://developers.google.com/drive/api/guides/about-sdk
 * https://stackoverflow.com/questions/53357741/how-to-perform-oauth-2-0-using-the-curl-cli
 * https://gist.github.com/LindaLawton/cff75182aac5fa42930a09f58b63a309
 * https://github.com/jay/curl_google_oauth
 * https://www.youtube.com/watch?reload=9&v=hBC_tVJIx5w&feature=youtu.be
 * https://www.daimto.com/how-to-get-a-google-access-token-with-curl/
 * https://www.youtube.com/watch?v=hBC_tVJIx5w
 * https://stackoverflow.com/questions/71364188/how-to-authorize-a-curl-script-to-google-oauth-after-oauth-out-of-band-oob-flo
 * https://github.com/alangrainger/obsidian-google-photos/blob/main/src/oauth.ts
 * https://developers.google.com/drive/api/reference/rest/v2#Files
 * https://stackoverflow.com/questions/51399187/oauth2-with-desktop-application-security
 * https://stackoverflow.com/questions/66043006/how-can-authorization-code-flow-with-pkce-be-more-secure-than-authorization-code
 * https://blog.postman.com/pkce-oauth-how-to/
 * https://www.googleapis.com/discovery/v1/apis/drive/v3/rest
 * https://github.com/Anmol-Singh-Jaggi/gDrive-auto-sync
 * https://stackoverflow.com/questions/35143283/google-drive-api-v3-migration/
 * https://rclone.org/drive/ https://github.com/rclone/rclone
 */

import {
    App,
    ButtonComponent,
    DropdownComponent,
    Modal,
    moment,
    Notice,
    Plugin,
    PluginSettingTab,
    Setting,
    TFolder,
    TFile,
	TAbstractFile,
} from 'obsidian';

// Debuglevels in increasing severity so messages >= indexOf(debugLevel) will be
// shown
const debugLevels = ["debug", "info", "warn", "error"];

let logError = function(message?: any, ...optionalParams: any[]) {};
let logWarn = function(message?: any, ...optionalParams: any[]) {};
// Note console.log is an alias of console.info
let logInfo = function(message?: any, ...optionalParams: any[]) {};
let logDbg = function(message?: any, ...optionalParams: any[]) {};

function hookLogFunctions(debugLevelIndex: number, tag: string) {
    logInfo("hookLogFunctions", debugLevelIndex, tag);

    const logIgnore = function(message?: any, ...optionalParams: any[]) {};
    logError = (debugLevelIndex <= debugLevels.indexOf("error")) ?
        console.error.bind(console, tag + "[ERROR]:") :
        logIgnore;
    logWarn = (debugLevelIndex <= debugLevels.indexOf("warn")) ?
        console.warn.bind(console, tag + "[WARN]:") :
        logIgnore;
    logInfo = (debugLevelIndex <= debugLevels.indexOf("info")) ?
        console.info.bind(console, tag + "[INFO]:") :
        logIgnore;
    logDbg = (debugLevelIndex <= debugLevels.indexOf("debug")) ?
        console.debug.bind(console, tag + "[DEBUG]:") :
        logIgnore;
}

function debugbreak() {
    debugger;
}


hookLogFunctions(debugLevels.indexOf("debug"), "GoogleDrive");

interface GoogleDriveSettings {
    debugLevel: string;
    accessToken: string;
    accessExpires: string;
    refreshToken: string;
    syncIntervalSecs: string;
    syncMode: string;
    syncStartTime: string;
    folderId: string;
    parentIds: string;
    browseOrphans: boolean;
    clientId: string;
    clientSecret: string;
    clientScope: string;
    redirectUri: string;
    encryptFilenames: boolean;
    encryptionPassword: string;
    compressFiles: boolean;
}

const DEFAULT_SETTINGS: GoogleDriveSettings = {
    debugLevel: 'debug',
    accessToken: '',
    accessExpires: '',
    refreshToken: '',
    // Empty to disable, positive nonzero to enable
    // XXX Periodic synchronization not implemented yet
    // XXX In the future 0 may mean watch changes (in theory allowed with
    //     drive.file scope?)
    syncIntervalSecs: '',
    syncMode: 'both',
    syncStartTime: '0',
    folderId: 'root',
    parentIds: '',
    browseOrphans: false,
    // obsidiangdrive clientId (web app)
    clientId: '800679030178-3pd3ct4pic1tkfn9l366a6uhak38gqio.apps.googleusercontent.com',
    clientSecret: '',
    clientScope: 'https://www.googleapis.com/auth/drive.file',
    redirectUri: 'http://localhost',
    // XXX Not implemented yet
    encryptFilenames: false,
    // XXX Not implemented yet
    encryptionPassword: '',
    // XXX Not implemented yet
    compressFiles: false,
}

type GoogleDriveFile = {
    id: string;
    name: string;
    mimeType: string;
    // In RFC 3339 date-time format, can be used as Date(string),
    // Date.parse(string)
    modifiedTime: string;
    createdTime: string;
};

type GoogleDriveFileList = {
	incompleteSearch: boolean;

	files: GoogleDriveFile[];
}

export default class GoogleDrive extends Plugin {
    settings: GoogleDriveSettings;

    accessToken: string | null;
    maxLoginRetries: number = 3;

    downloadChanges: boolean = true;
    uploadChanges: boolean = true;

    loginPromise: Promise<boolean> | null = null;
    refreshPromise: Promise<Response> | null = null;

    // 0 no sync, positive nonzero sync, negative filtered out beforehand.
    // Initialized to zero to force toggle if enabled in the configuration
    syncIntervalSecs: number = 0;
    syncIntervalId: number | null = null;

	deleteQueue: Array<TAbstractFile> = [];

    async onload() {
        logInfo("onload");


        /* XXX Can't be used since google doesn't allow app urls in the oauth2
               config page?

        // Register obsidian://gdriveresponse as a response for the token
        this.registerObsidianProtocolHandler('gdriveresponse', (data:
        ObsidianProtocolData) => { logInfo("handler returns", data);
        });*/

        await this.loadSettings();

        this.addRibbonIcon('sync', 'Synchronize vault with Google Drive', (evt: MouseEvent) => {
            this.syncVault();
        });

		// Listen for delete operations so we can delete those files on
		// Google Drive, as well.
		this.app.vault.on('delete', (abstractFile: TAbstractFile) => {
			this.deleteQueue.push(abstractFile);
			logInfo("added to delete queue:");
			logInfo(abstractFile);
		});

        this.addCommand({
            id: 'open-login-modal',
            name: 'Open login modal',
            callback: async () => {
                // XXX Should this use the loginPromise since it could happen
                //     that when this modal is shown the synchronization
                //     interval kicks in and needs to authenticate? Or should
                //     the interval just pop a notice in that case since it's
                //     possible the dialog is canceled without realizing the
                //     synchronization is needed?
                await new Promise((resolve, reject) => {
                    new LoginModal(this, false, resolve, reject).open();
                });
            }
        });

        this.addCommand({
            id: 'show-debug-information',
            name: 'Show debug information',
            callback: () => {
                const fragment = createFragment(fragment => {
                    fragment.createDiv({ text: (this.settings.clientId != DEFAULT_SETTINGS.clientId) ? "Non-default ClientId" : "Default ClientId" });
                    fragment.createDiv({ text: (this.settings.clientSecret != DEFAULT_SETTINGS.clientSecret) ? "Non-default ClientSecret" : "Default ClientSecret" });
                    fragment.createDiv({ text: (this.settings.clientScope != DEFAULT_SETTINGS.clientScope) ? "Non-default ClientScope" : "Default ClientScope" });
                    fragment.createDiv({ text: JSON.stringify(this.settings, undefined, 4) } );
                });

                const notice = new Notice(fragment, 0);
                // XXX Find a better way of doing scroll, this shows the
                //     scrollbar on the notice container which is outside the
                //     notice bounds
                const noticeContainer = notice.noticeEl.parentElement as HTMLElement;
                noticeContainer.style.maxHeight = "100%";
                noticeContainer.style.overflow = "scroll";
            }
        });

        // XXX Add single folder sync command
        // XXX Add single file sync command
        // XXX Split between sync from and sync to?
        this.addCommand({
            id: 'synchronize-vault',
            name: 'Synchronize Vault',
            checkCallback: (checking: boolean) => {
                // Conditions to check
                if ((this.settings.accessToken != '') && (this.settings.folderId != '')) {
                    if (!checking) {
                        this.syncVault();
                    }
                    return true;
                }
            }
        });

        this.addSettingTab(new GoogleDriveSettingsTab(this.app, this));
    }

    onunload() {
        logInfo("onunload");
    }

    parseSettings(settings: GoogleDriveSettings) {
        // Hook log functions as early as possible so any console output is seen
        // if enabled
        hookLogFunctions(debugLevels.indexOf(settings.debugLevel), "GoogleDrive");

        this.uploadChanges = ((settings.syncMode == 'both') || (settings.syncMode == 'upload'));
        this.downloadChanges = ((settings.syncMode == 'both') || (settings.syncMode == 'download'));

        let syncIntervalSecs = parseInt(settings.syncIntervalSecs);
        syncIntervalSecs = isNaN(syncIntervalSecs) ? 0 : Math.max(0, syncIntervalSecs);

        // XXX This does work on every edit update, add an ok/cancel button?
        if (this.syncIntervalSecs != syncIntervalSecs) {
            if (this.syncIntervalId != null) {
                logInfo("Clearing syncInterval id", this.syncIntervalId);
                window.clearInterval(this.syncIntervalId as number);
                // XXX Missing unregistering with Obsidian, but it there doesn't
                //     seem to be a way to do that, but it's not a big issue since:
                //     1. the Obsidian registered function only does clearInterval
                //     2. clearInterval on invalid ids is ignored
                //     3. ids are not recycled as per javscript spec
                this.syncIntervalId = null;
            }

            this.syncIntervalSecs = syncIntervalSecs;

            if (this.syncIntervalSecs != 0) {
                this.syncIntervalId = window.setInterval(() => {

                    logWarn('Periodic synchronization not implemented yet');
                    // XXX Missing implementing periodic synchronization, needs
                    //     to resolve what happens if it fails due to login,
                    //     internet, etc (is annoying the user with a popup ok
                    //     or should it just warn?), preventing simultaneous
                    //     syncFolder calls, etc. Should also call some function
                    //     common with the command rather than replicating the
                    //     syncFolder call

                    // this.syncFolder(settings.folderId, this.app.vault.getRoot());
                }, this.syncIntervalSecs * 1000);
                logInfo("Setting syncInterval id", this.syncIntervalId, "secs",
                    this.syncIntervalSecs);

                this.registerInterval(this.syncIntervalId);
            }
        }
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        this.parseSettings(this.settings);
    }

    async saveSettings() {
        await this.saveData(this.settings);
        this.parseSettings(this.settings);
    }

    async fetchApi(endpoint: string, method: string = 'GET', params:any = null, init: RequestInit|null = null): Promise<Response> {

        let loginRetries = 0;
        let resp;

        while (true) {
            // Fill with defaults

            init = Object.assign({
				method: method
			}, init);

            init.headers = Object.assign(init.headers||{}, { 'Authorization': 'Bearer ' + this.settings.accessToken})
            const query = (params == null) ? "" : '?' + new URLSearchParams(params).toString();
            logInfo("fetchApi doing fetch", init, query);
            resp = await fetch(
                'https://www.googleapis.com/' + endpoint + query,
                init
            );

            // XXX Missing filtering out all non auth-related errors, see below

            if ((!resp.ok) && (resp.status != 404)) {
                // Return is normally an error object json with
                // - auth error: status=401, error.code = 401, error.status = UNAUTHENTICATED, error.errors[0].reason=authError
                // - invalid query: status=400, error.code = 400, error.status = undefined, error.errors[0].reason=invalid, invalidPameter...
                // - internal error: status=500, error.code = 500, error.reason = internalError (gets fixed by retrying)
                // - auth error: status=403, error.code = 403, error.status=PERMISSION_DENIED, error.errors[0].reason=forbidden (missing valid API key (!))
                // - error: status=403, error.code= 403, error.status=undefined, error.errors[0].reason="fileNotDownloadable" (trying to download folders or Google docs)
                // - file not found error: status=404, error.code = 404, error.status=undefined, error.errors[0].reason="notFound" (fetchFolderPath trying to get the root name and parents when in drive.file scope)
                logWarn("fetchApi failed", resp.status, resp.statusText);
                if (resp.headers.get("content-type") == "application/json; charset=UTF-8") {
                    logWarn("fetchApi error json", await resp.json());
                }
                loginRetries++;
                if (loginRetries > this.maxLoginRetries) {
                    logError("Maximum login retries", this.maxLoginRetries, "exceeded");
                    break;
                }

                // If there's a refresh token, try to use it
                // See https://developers.google.com/identity/protocols/oauth2/web-server#httprest_7
                if (this.settings.refreshToken != '') {
                    logInfo("Refreshing token");
                    const tokenParams = new URLSearchParams({
                        client_id: this.settings.clientId,
                        client_secret: this.settings.clientSecret,
                        grant_type: 'refresh_token',
                        refresh_token: this.settings.refreshToken,
                    });

                    // It's possible fetchApi is called from two places
                    // simultaneously (eg the settings dialog box does it for
                    // resolving the path and filling in the folders), and the
                    // result is that there may be a double refresh of the
                    // access token which is a waste of access tokens since
                    // there's some limit and older access tokens start being
                    // revoked after that limit.
                    //
                    // Use a promise so only one refresh call is made and other
                    // fetchApi calls around that time on that promise to be
                    // resolved. The promise is slightly complex because it needs
                    // to resolve the json if necessary
                    let p = this.refreshPromise;
                    if (p == null) {
                        logInfo("Creating refreshPromise");
                        p = new Promise<Response>((resolve, reject) => {
                            let p = fetch("https://oauth2.googleapis.com/token", {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded'
                                },
                                body: tokenParams
                            }).then(async resp => {
                                if (resp.ok) {
                                    let jsonResp = await resp.json();
                                    logInfo("refresh token succeeded", resp, jsonResp);
                                    this.settings.accessToken = jsonResp.access_token;
                                    this.settings.accessExpires = moment().add(jsonResp.expires_in, 'second').format();
                                } else {
                                    logError("refresh token failed", resp, resp.status, resp.statusText);
                                    if (resp.headers.get("content-type") == "application/json; charset=UTF-8") {
                                        logWarn("fetchApi error json", await resp.json());
                                    }
                                    this.settings.accessToken = '';
                                    this.settings.refreshToken = '';
                                }
                                await this.saveSettings();
                                resolve(resp);
                            })
                        });
                        this.refreshPromise = p;
                    } else {
                        logInfo("Reusing refreshPromise");
                    }
                    resp = await p;
                    if (this.refreshPromise != null) {
                        // Make the first waiter to wake up to reset the promise
                        this.refreshPromise = null;
                    }
                }

                // If there's no refresh token or refresh failed, prompt
                if (!resp.ok) {
                    logInfo("fetchApi prompting for login");
                    // If there's already a login dialog box, share that promise
                    // instead of popping another login dialog box. This
                    // prevents having multiple dialog boxes behind each other
                    // in cases where there can be multiple fetchApi calls
                    // waiting to reauthenticate (eg in the settings dialog box
                    // where folder population and path conversion perform
                    // one fetchApi call while the other is outstanding)
                    let p = this.loginPromise;
                    if (p == null) {
                        logInfo("Creating loginPromise");
                        p = new Promise( (resolve, reject) => {
                            let login = new LoginModal(this, true, resolve, reject);
                            login.open();
                        });
                        this.loginPromise = p;
                    } else {
                        logInfo("Reusing loginPromise");
                    }
                    let ok = await p;
                    // Make the first waiter to wake up to reset the promise
                    if (this.loginPromise != null) {
                        this.loginPromise = null;
                    }
                    if (!ok) {
                        // Not closed with Ok, prevent retry
                        //
                        // XXX Verify this bubbles up to the topmost function so
                        //     a cancel also aborts any folder synchronization
                        //     etc instead of continuously popping the dialog
                        //     box?
                        break;
                    }
                }
            } else {
                break;
            }
        }

        return resp;
    }

    async fetchJson(endpoint: string, params: any = null, init: RequestInit|null=null) {
        return this.fetchApi(endpoint, "GET", params, init).then(resp => {
            return resp.json();
        });
    }

    async fetchFiles(folderId: string, files: GoogleDriveFile[] = [], pageToken: string = ''): Promise<GoogleDriveFile[]> {
        logInfo("fetchFiles", folderId, pageToken);
        const params = {
            q: "('" + folderId + "' in parents) and (not trashed)",
            fields: "nextPageToken, files(id, name, mimeType, modifiedTime, createdTime)",
            pageToken: pageToken
        };
        return this.fetchJson('drive/v3/files', params).then(resp => {
            logInfo(resp);
            resp.files.forEach((f: GoogleDriveFile) => {
                files.push(f);
            });

            if (resp.nextPageToken !== undefined) {
                return this.fetchFiles(folderId, files, resp.nextPageToken);
            } else {
                return files;
            }
        });
    }

	async deleteFile(fileId: string): Promise<void> {
		logInfo("deleteFiles", fileId);

		return this.fetchApi(`drive/v3/files/${fileId}`, "DELETE")
			.then((response) => {
				logInfo("Response received from delete: ", response);
			});
	}

    async fetchCreateFolder(parentId: string, folderName: string) {
        // POST https://www.googleapis.com/upload/drive/v3/files?uploadType=media
        // See https://developers.google.com/drive/api/guides/manage-uploads#simple
        // See https://developers.google.com/drive/api/guides/folder#node.js
        logInfo("fetchCreateFolder", parentId, folderName);
        const metadata = { name : folderName, mimeType : 'application/vnd.google-apps.folder', parents : [parentId]};
        const init = {
            method: "POST",
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(metadata)
        };
        return this.fetchJson('drive/v3/files', null, init);
    }

    async fetchFolderPath(folderId: string): Promise<string> {
        logInfo("fetchFolderPath", folderId);
        const params = { fields: 'name,parents' };
        return this.fetchJson('drive/v3/files/' + folderId, params).then(resp =>  {
            logInfo("fetchFolderPath", resp);

            // When using drive.file scope, trying to get the name and parents
            // of the root folder will return 404, trap it and assume it's the
            // root
            if (resp?.error?.code == 404) {
                return "/";
            }

            // Note parents is undefined for "Computers" folders but length
            // 0 for 'root', allow both

            if ((resp.parents !== undefined) && (resp.parents.length > 0)) {
                // Note Google Drive was changed to be limited to single parent,
                // so just need to check the first parent
                return this.fetchFolderPath(resp.parents[0]).then(path => {
                    return path + resp.name + "/";
                });
            } else {
                return resp.name + "/";
            }
        });
    }

    async syncVault() {
        logInfo("syncVault");
        // XXX Rationalize these checks all over the file
        if ((this.settings.accessToken != '') && (this.settings.folderId != '')) {
            const syncStartTime = Date.now();

			// Delete any files remotely that are in the delete queue.
			while (this.deleteQueue.length > 0) {
				let nextAbstractFileToDelete = this.deleteQueue.pop();
				// let abstractFilePaths = nextAbstractFileToDelete?.path.split("/");
				// console.log("***** DEBUG_jwir3: abstract file path of deletion target: ", abstractFilePaths);
				let searchResults: GoogleDriveFileList = await this.findFolderByRelativePath(nextAbstractFileToDelete?.path, this.settings.folderId);
				// Retrieve the id from the first result, if it's found
				if (searchResults.files.length > 0) {
					let resultingFile = searchResults.files[0];
					logInfo("***** DEBUG_jwir3: Found resulting file: ", resultingFile);
					await this.deleteFile(resultingFile.id);
				}
				// console.log("***** DEBUG_jwir3: Resulting file: ", folderPath);
			}

            this.syncFolder(this.settings.folderId, this.app.vault.getRoot()).then(async ()=> {
                this.settings.syncStartTime = syncStartTime.toString();
                await this.saveSettings();
            });
        }
    }

    async syncFolder(folderId: string, vaultFolder: TFolder) {
        // Note the TAbstractFile.path is the path to this vault folder relative
        // to the vault root, including the folder's name so there's no need to
        // concat path and name

        // XXX Note when syncing the root this won't sync orphaned folders
        //     despite those being shown on the dropdown, do we care? (orphaned
        //     folders can still be synced individually by passing the orphan
        //     folderId)

        logInfo("syncFolder", folderId, vaultFolder.path);

        // XXX Have a setting to hide these
        const notice = new Notice('Synchronizing ' + vaultFolder.path);

        // List both, sort, create newer, delete unexistent, update newer

        // This returns all files in the vault, including those in subdirs
        // - path contains the vault relative full path (no leading forward slash),
        // - name contains only the name
        // - parent is a TFolder, and path is "/" for the root folder
        // - deleted is a deletion flag

        // Do a copy since children may be modified below
        let vaultFiles = vaultFolder.children.slice();
        const vault = vaultFolder.vault;

        vaultFiles.sort((a,b) => a.name.localeCompare(b.name));

        logInfo("vaultFiles", vaultFiles);

        let driveFiles = await this.fetchFiles(folderId);
        driveFiles.sort((a, b) => a.name.localeCompare(b.name));
        logInfo("driveFiles", driveFiles);

        // Copy from google drive to the vault, recursively if necessary

        // XXX Use HTTP If-match or If-unmodified-since header, to prevent race
        //     conditions with two clients updating at the same time (not
        //     supported but they could have sync interval set). Looks google
        //     drive v3 doesn't report etags in the metadata (even if the
        //     performance guide states it does) so either use v2 or use
        //     If-Unmodified-since
        //     See https://developers.google.com/drive/api/guides/performance
        //     See https://stackoverflow.com/questions/42174600/alternative-for-etag-field-in-google-drive-v3
        // XXX Maybe etags are supported in the HTTP header? At least the GET
        //     alt=media response doesn't have an etag field
        // XXX Use the changes api?

        // XXX This fails for files deleted from google, needs to either
        //     - check the google drive changes API
        //     - replicate google drive changes API by storing a sync journal
        //       with deleted files in the google drive, maybe per user or atomic
        //       updates with HTTP If- headers
        //     - check trash flag (but google drive delete doesn't go through
        //       trash - trashing is a files update with trash : true - the trash
        //       can be emptied, etc)
        //     - detect deletions as follows:
        //       - if a vault file is not on google drive and the google drive
        //         file is older than the last sync time, delete from google
        //         drive, upload to google drive otherwise
        //       - if a google drive file is not on the vault and the vault file
        //         is older than the last sync time, delete from vault, download
        //         to vault ortherwise
        //       This could store the absolute last sync time on the drive as
        //       well for more accurate check, but it's not clear it's useful

        // XXX Have an option to delete to trash on Google Drive, delete to
        //     trash on vault


        // XXX Same thing for renamed files (a rename could be implemented as a
        //      deletion + creation?)

        // File is on both
        // - if the drive file is newer, overwrite the vault file
        // - if the drive file is older, overwrite the drive file
        // - if they have the same date, ignore
        // File is only on vault, copy to google
        // File is only on drive, copy to vault

        let id = 0;
        let iv = 0;
        // XXX Have a setting to hide these
        const fileNotice = new Notice('Synchronizing ' + vaultFolder.path);
        while ((id < driveFiles.length) || (iv < vaultFiles.length)) {
            const vaultFile = (iv < vaultFiles.length) ? vaultFiles[iv] : null;
            const driveFile = (id < driveFiles.length) ? driveFiles[id] : null;

            logInfo("Comparing vault", iv, vaultFile?.name, "to drive", id, driveFile?.name);

            const vaultIsFolder = (vaultFile instanceof TFolder);
            const driveIsFolder = (driveFile?.mimeType == 'application/vnd.google-apps.folder');
            let update = false;

            let cmp;
            if (vaultFile == null) {
                cmp = 1;
            } else if (driveFile == null) {
                cmp = -1;
            } else {
                cmp = vaultFile.name.localeCompare(driveFile.name);
            }

            if (cmp == 0) {
                // Cast for shorthand and to get rid of overzealous es-lint
                // errors about files being possibly null
                const vfile = vaultFile as TFile;
                const dfile = driveFile as { id: string, name: string, modifiedTime: string };
                fileNotice.setMessage(vfile.name);
                if (vaultIsFolder != driveIsFolder) {
                    // Folder vs. file mismatch but vault folders don't have
                    // dates so there's no way to resolve the conflict
                    // XXX Missing conflict resolution folder vs. file
                    logError("Folder vs. file mismatch for", vfile.name, dfile.name);
                } else if (vaultIsFolder) {
                    // Both are folders, recurse
                    logInfo("Recursing folder", dfile.name, vfile.name);
                    await this.syncFolder(dfile.id, vaultFile);
                } else {
                    // Both are files, get the newest
                    const gtime = Date.parse(dfile.modifiedTime);
                    const vtime = vfile.stat.mtime;
                    const dcmp = gtime - vtime;
                    // XXX This time comparison can fail showing one millisecond
                    //     of difference (vault one less than drive), not clear
                    //     if it's a problem when uploading to Google Drive
                    //     setting the time? Currently worked around by checking
                    //     against +-1 instead of 0
                    //
                    //     One theory is that because the file update sends the
                    //     file data after the metadata, it's possible google is
                    //     re-updating the metadata at that point?
                    //     If so, this could be fixed by sending the metadata
                    //     after the file data? But the multipart file upload
                    //     fails with a server error if the metadata comes after
                    //     the file  data in the multipart transaction, so it
                    //     will probably require an independent metadata update?
                    if (dcmp < -1) {
                        // Copy vault to google drive
                        // XXX If the drive file is newer than the last sync
                        //     date, then there's a conflict and the user should
                        //     decide?
                        logInfo("Will copy from vault", dcmp, vfile.name, "to drive", dfile.name, gtime, new Date(gtime), "<", vtime, new Date(vtime));
                        cmp = -1;
                        update = true;
                    } else if (dcmp > 1) {
                        // Copy google drive to vault

                        // XXX There could be bad interactions here with edit
                        //     history files:
                        //
                        //     - If a file is copied from google drive before
                        //       its history file, the modification callback will
                        //       be triggered and create an entry for that edit,
                        //       which can either race with the google drive of
                        //       the history file, cause this loop to use stale
                        //       information
                        //
                        //     - If an edit history file is copied before its file,
                        //       this is probably ok since when the file is copied,
                        //       there will be zero diffs and the history file not
                        //       updated.
                        //
                        //    One workaround is to blacklist history files from
                        //    syncrhonizing, which is not too bad since it will
                        //    still record the edit due to the synchronization
                        //    in the history

                        logInfo("Will copy from drive", dcmp, dfile.name, "to vault", vfile.name, gtime, new Date(gtime), ">", vtime, new Date(vtime));
                        cmp = 1;
                        update = true;
                    } else {
                        // Nothing to do if same time
                        logInfo("Ignoring same time", dcmp, gtime, new Date(gtime),"vs", vtime, new Date(vtime), "drive", dfile.name, "as vault", vfile.name);
                    }
                }
                // XXX This breaks when multiple files in the google drive have
                //     the same name(!), appear as (1) (2), etc on Total
                //     Commander but the name returned by google drive is the
                //     same (check title instead?)
                if (cmp != -1) {
                    iv++;
                }
                if (cmp != 1) {
                    id++;
                }
            }
            if (cmp == -1) {
                // Vault file/folder not in drive
                fileNotice.setMessage(vaultFile?.name as string);
                if (this.uploadChanges)  {
                    if (vaultIsFolder) {
                        // If folder, create in drive and recurse
                        logInfo("Creating drive folder", vaultFile.name);
                        const resp = await this.fetchCreateFolder(folderId, vaultFile.name);
                        let subFolderId = resp.id;
                        // XXX Needs to check for errors

                        logInfo("Recursing folder", vaultFile.name, vaultFile.name);
                        await this.syncFolder(subFolderId, vaultFile);
                    } else {
                        // If file, upload to drive

                        // Cast for shorthand and to get rid of wrong typescript
                        // errors about files being possibly null
                        const vfile = vaultFile as TFile;

                        logInfo("Uploading to drive", vfile.name, "from vault", vfile.name);

                        // XXX There are two possible race conditions here:
                        //
                        //     - The file contents are more recent than the
                        //       metadata, not an issue, the next sync will
                        //       update the metadata
                        //
                        //     - The file was deleted after fetching the metadata
                        //       verify that syncFolder fails and is resumable
                        //       next time

                        // XXX Verify a partially successful syncFolders doesn't
                        //     cause corruption and is resumable next time

                        const buffer = await vault.readBinary(vfile);
                        // Don't bother resolving the right mime type here,
                        // Google Drive will exchange this generic type with a
                        // more specific one, even on unkown extensions (ie it's
                        // able to set gzip to .edtz files)
                        const mimeType = 'application/octet-stream';
                        const metadata = {
                            name : vfile.name,
                            modifiedTime: new Date(vfile.stat.mtime).toISOString(),
                            createdTime: new Date(vfile.stat.ctime).toISOString(),
                            mimeType : mimeType,
                            parents : [folderId],
                        };
                        const updateMetadata = {
                            // Note google drive will fail with 403 if
                            // createdTime is updated, it can only be set at
                            // creation time
                            modifiedTime: new Date(vfile.stat.mtime).toISOString(),
                        };

                        // XXX Needs resumable upload method for big >5MB sizes

                        const form = new FormData();
                        // Sending the metadata before the file is believed to
                        // cause a bug where the sometimes the drive file
                        // modified date would be one millisecond older than the
                        // vault file, so send the metadata after the file. This
                        // also requires setting the filename parameter for the
                        // form 'file' part or the call will return error

                        // XXX Sending metadata after the file in the same
                        //     multipart transaction fails with 403 for PATCH,
                        //     even with the file field, can't be done with
                        //     multipart will need to be changed to two separate
                        //     api calls to prevent the random 1ms modifiedTime
                        //     issue?
                        //     See https://rclone.org/drive/#modified-time
                        form.append('metadata', new Blob([JSON.stringify(update ? updateMetadata : metadata)], {type: 'application/json; charset=UTF-8'}));
                        form.append('file', new Blob([buffer], {type: mimeType}));
                        // XXX Google Drive will silently rename to (1), (2),
                        //     etc if a "POST" is done on a file with the same
                        //     name
                        const params = { uploadType: 'multipart' };
                        // Note dirveFile can't be null if doing an udpate,
                        // silent the es-lint error by using "?"
                        const query = (update ? "/" + driveFile?.id : "");
                        const init = {
                            method: update ? "PATCH" : "POST",
                            body: form
                        };
                        let resp = await this.fetchJson('upload/drive/v3/files' + query, params, init);
                        // The response has the resolved mimeType
                        logInfo(resp);

                        // XXX Missing error checks
                    }
                }

                iv++;
            } else if (cmp == 1) {
                // Google drive file/folder not in vault
                fileNotice.setMessage(driveFile?.name as string);
                if (this.downloadChanges) {

                    // Cast for shorthand and to get rid of wrong typescript errors
                    // about files being possibly null
                    const dfile = driveFile as { id: string, name: string, modifiedTime: string, createdTime: string };

                    let vaultFilepath = dfile.name;
                    // Path for items in the root is "/", ignore that one since the
                    // vault api fails for forward slash prefixed paths
                    if (vaultFolder.path != "/") {
                        // Non-root paths are not forward slash terminated, add it
                        vaultFilepath = vaultFolder.path + "/" + vaultFilepath;
                    }

                    if (driveIsFolder) {
                        // If folder, create and recurse

                        logInfo("Creating vault folder", vaultFilepath);
                        await vault.createFolder(vaultFilepath).catch((error) => null);
                        let vaultSubFolder = vault.getAbstractFileByPath(vaultFilepath);

                        if (vaultSubFolder instanceof TFolder) {
                            logInfo("Recursing folder", dfile.name, dfile.name);
                            await this.syncFolder(dfile.id, vaultSubFolder);
                        } else {
                            // Can't create the folder (file was created behind our
                            // back or some other error)
                            logError("Can't create folder", vaultFilepath, ", ignoring", dfile.name);
                        }

                    } else {
                        // If file, download to vault
                        logInfo("Downloading from drive", dfile.name, "to vault", dfile.name);

                        // XXX This needs to

                        const resp = await this.fetchApi('drive/v3/files/' + dfile.id, "GET", { alt: 'media' });
                        const buffer = await resp.arrayBuffer();
                        try {

                            // XXX There are two possible race conditions here:
                            //
                            //     - the contents could be more recent than
                            //       modifiedTime, this could be fixed by using
                            //       an If-unmodified header is probably not an
                            //       issue, in the next sync the metadata will
                            //       be updated and the contents re-downloaded
                            //
                            //     - the file could have been deleted, this will
                            //       probably result in syncFolders aborting?

                            // Note createbinary and modifyBinary seem work fine
                            // for both text and binary files, so use that
                            // disregarding the type
                            if (update) {
                                await vault.modifyBinary(vaultFile as TFile, buffer, { mtime: Date.parse(dfile.modifiedTime), ctime: Date.parse(dfile.createdTime)} );
                            } else {
                                await vault.createBinary(vaultFilepath, buffer, { mtime: Date.parse(dfile.modifiedTime), ctime: Date.parse(dfile.createdTime)} );
                            }
                            logInfo("Copied", buffer.byteLength, "bytes");
                        } catch (e) {
                            // XXX This triggers if the file already exists, handle
                            //     conflicts/ask
                            // XXX Check if anything is needed for Obsidian to refresh
                            //     if the file is currently being displayed. Careful with
                            //     disturbing the editor if it's currently being edited
                            //     and this is run on a timer
                            logError("Error createBinary", e);
                        }
                    }
                }

                id++;
            }
        }

        notice.setMessage('Synchronized ' + vaultFolder.path);
    }

	async findFolderByRelativePath(path: string|undefined, folderId: string): Promise<GoogleDriveFileList> {
		if (path) {
			const splitPath = path.split("/");
			const queryParams = {
				q: `name = '${splitPath[splitPath.length - 1]}'`
			};

			console.log("***** DEBUG_jwir3: file path: ", path);

			return this.fetchJson('drive/v3/files', queryParams).then(resp => {
				logInfo('***** DEBUG_jwir3: Saw response for findFolderByRelativePath: ', resp);
				return resp;
			});
		}

		return Promise.resolve({ files: [], incompleteSearch: true} as GoogleDriveFileList);
	}
}

class TextInputModal extends Modal {
    title: string;
    prompt: string;
    onSubmit: (result: string) => void;

    result: string;

    constructor(app: App, title: string, prompt: string, onSubmit: (result: string) => void) {
        super(app);

        this.title = title;
        this.prompt = prompt;
        this.onSubmit = onSubmit;
    }

    onOpen() {
        const { contentEl } = this;

        this.titleEl.setText(this.title);

        // XXX This should accept on enter
        new Setting(contentEl)
            .setName(this.prompt)
            .addText((text) =>
                text.onChange((value) => {
                this.result = value
                }));

        new Setting(contentEl)
            .addButton((btn) =>
                btn
                .setButtonText("Ok")
                .setCta()
                .onClick(() => {
                    this.close();
                    this.onSubmit(this.result);
                }))
            .addButton((btn) =>
                btn
                .setButtonText("Cancel")
                .onClick(() => {
                    this.close();
                }));
    }

    onClose() {
        let { contentEl } = this;
        contentEl.empty();
    }
}

class LoginModal extends Modal {
    plugin: GoogleDrive;
    resolve: any;
    reject: any;
    ok: boolean;
    showGoogleCloudConfiguration: boolean = false;
    showOkCancel: boolean;

    constructor(plugin: GoogleDrive, showOkCancel: boolean, resolve: any, reject: any) {
        super(plugin.app);
        this.plugin = plugin;
        this.resolve = resolve;
        this.reject = reject;
        this.showOkCancel = showOkCancel;
    }

    buildAuthParams() {
        let authParams:any;
        if (this.plugin.settings.clientSecret == '') {
            // web app implicit flow
            // https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow
            authParams = {
                client_id: this.plugin.settings.clientId,
                // The google auth2 form doesn't allow internal urls like
                // obsidian://gdriveresponse and Using fetch causes CORS error
                // 'app://obsidian.md' has been blocked by CORS policy: No
                // 'Access-Control-Allow-Origin' header is present on the
                // requested resource.
                redirect_uri: this.plugin.settings.redirectUri,
                // XXX This returns the access token directly, should probably use
                //     'code' so it can be converted to an access token and refresh
                //     token?
                // XXX 'code' requires client secret, but token does not
                response_type: 'token',
                // Note the scope is valid for the duration of this token and
                // any refreshed token, so limiting the scope after the fact
                // doesn't do anything
                scope: this.plugin.settings.clientScope,
                // XXX drive.file scope only allows working with files created
                //     by this app, investigate?
                //scope: 'https://www.googleapis.com/auth/drive',
            };
        } else {
            // web server offline flow
            authParams = {
                client_id:  this.plugin.settings.clientId,
                // The google auth2 form doesn't allow internal urls like
                // obsidian://gdriveresponse and Using fetch causes CORS error
                // 'app://obsidian.md' has been blocked by CORS policy: No
                // 'Access-Control-Allow-Origin' header is present on the
                // requested resource.
                redirect_uri : this.plugin.settings.redirectUri,
                // XXX This returns the access token directly, should probably use
                //     'code' so it can be converted to an access token and refresh
                //     token?
                // XXX 'code' requires client secret, but token does not
                response_type: 'code',
                // Note the scope is valid for the duration of this token and
                // any refreshed token, so limiting the scope after the fact
                // doesn't do anything
                scope: this.plugin.settings.clientScope,
                // Taken from oauth 2.0 playfround at https://developers.google.com/oauthplayground/
                // See https://stackoverflow.com/questions/11475101/when-is-access-type-online-appropriate-oauth2-google-api
                // Setting to offline is necessary so a refresh_token is
                // provided
                access_type: 'offline',
                // Set to "consent" to force a consent prompt to the user and
                // return a refresh token, otherwise if the app already has an
                // unexpired token, it will be given an access token without
                // refresh token. This is the equivalent to the deprecated
                // "approval_prompt" some examples use.
                // See https://stackoverflow.com/questions/10827920/not-receiving-google-oauth-refresh-token
                // See https://developers.google.com/identity/protocols/oauth2/web-server#request-parameter-prompt
                // See https://developers.google.com/identity/openid-connect/openid-connect#re-consent
                //
                // Refresh tokens are said to last 6 months but test ones only 7
                // days. There's also a limit on per account per client id tokens
                // See https://developers.google.com/identity/protocols/oauth2#expiration
                // XXX Have a slider to force consent dialog?
                // XXX Force only if there's no refresh token? or force it
                //     unconditionally since when this is run the token has been
                //     lost anyway and only if the client has cookies won't have
                //     to consent?
                prompt: 'consent',
            };
        }
        // XXX Investigate if there's a way of not having to reveal the secret
        //     but still have refresh tokens with desktop app flow?
        //     https://developers.google.com/identity/protocols/oauth2/native-app

        return authParams;
    }

    updateAuthLink(authLink: HTMLAnchorElement) {
        const authParams = this.buildAuthParams();
        const authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams(authParams);
        logInfo("updateAuthLink", authUrl);
        authLink.href = authUrl;
    }

    setGoogleCloudConfigurationVisible(settings: Setting[], visible: boolean) {
        for (let apiSetting of settings) {
            if (visible) {
                apiSetting.settingEl.show();
            } else {
                apiSetting.settingEl.hide();
            }
        }
    }

    onOpen() {

        const {contentEl} = this;
        this.ok = false;

        this.titleEl.setText("Google Drive login for vault ");
        this.titleEl.createEl("i", { text: this.plugin.app.vault.getName() });

        // XXX Allow importing the configuration from a Google Cloud json file,
        //     maybe even from Google Drive?
        new Setting(contentEl)
            .setName("Display Google Cloud API configuration (advanced)")
            .setDesc("If you have a Google Cloud account, you can enter "+
                "your own Google Cloud API configuration. Otherwise, the plugin "+
                "will use its default configuration which requires reauthorization every hour.")
            .addToggle(toggle => toggle
                .setValue(this.showGoogleCloudConfiguration)
                .onChange(async (value) => {
                    logInfo("Show Google Cloud Configuration: " + value);
                    this.showGoogleCloudConfiguration = value;
                    this.setGoogleCloudConfigurationVisible(apiConfigSettings, this.showGoogleCloudConfiguration);
            })
        );

        // In order to login to google drive, a two step process is used:
        // - The user clicks on a link that contains the oauth2 request
        // - The oauth2 response tries to access an HTTP server and fails, but
        //   the failing url contains the access token. The user needs to copy
        //   the failing url into the edit box and the access token can then
        //   be extracted

        // This seems to be the easiest way to integrate oauth2 in obsidian,
        // given Google's oauth2 redirect_uri and javascript domain restrictions:
        // - Obsidian allows to register obsidian:// urls but the google oauth2
        //   form doesn't allow internal urls like obsidian://blah
        // - In addition, using fetch from inside Obsidian causes CORS error
        //   'app://obsidian.md' has been blocked by CORS policy: No
        //   'Access-Control-Allow-Origin' header is present on the requested
        //   resource.
        // - Trying to use Google's javascript client apis returns a
        //   storagerelay://file/?id=XXXX redirect_uri, which is allowed by
        //   oauth2 if the application is registered as web app, but then the
        //   registered javascript domains requires localhost as CORS domain so
        //   it won't work from inside obsidian either
        // In summary all the above requires either an HTTP server on localhost
        // or elsewhere, which makes it cumbersome than the two step process.

        // XXX Another option is to launch an Obsidian browser window, which is
        //     not supported on mobile, this could launch an Obsidian browser
        //     window on desktop and do the copy on mobile?
        let apiConfigSettings = Array();

        apiConfigSettings.push(new Setting(contentEl)
            .setName('Google API Client Id')
            .setDesc('Enter your Google API Client Id. Leave blank to use the default one.')
            .addText(text => text
                .setPlaceholder('Use default Client Id')
                .setValue(this.plugin.settings.clientId)
                .onChange(async (value) => {
                    logInfo('clientId: ' + value);

                    this.plugin.settings.clientId = value || DEFAULT_SETTINGS.clientId;
                    await this.plugin.saveSettings();

                    this.updateAuthLink(authLink);
                }
            )
        ));

        apiConfigSettings.push(new Setting(contentEl)
            .setName('Google API Client Secret')
            .setDesc("Enter your Google API Client Secret. Leave blank to not use a client secret, but will cause hourly re-authorization prompts.")
            .addText(text => { text
                .setPlaceholder("Don't use Client Secret")
                .setValue(this.plugin.settings.clientSecret)
                .onChange(async (value) => {
                    logInfo('clientSecret: ' + value);

                    this.plugin.settings.clientSecret = value || DEFAULT_SETTINGS.clientSecret;
                    await this.plugin.saveSettings();

                    this.updateAuthLink(authLink);
                })
                .inputEl.type = "password";
            })
            .addButton(button => button
                .setIcon("eye")
                .onClick(() => {
                    const inputEl = button.buttonEl.previousElementSibling as HTMLInputElement;
                    const isPassword = (inputEl.type == "text");
                    inputEl.type = isPassword ? "password" : "text";
                    button.setIcon(isPassword ? "eye" : "eye-off");
                })
            )
        );

        apiConfigSettings.push(new Setting(contentEl)
            .setName('Google API scope')
            .setDesc("Enter the Google API scope to use. Leave blank to use the default scope which will restrict to Google Drive folders created with this app.")
            .addText(text => { text
                .setPlaceholder("Use default scope")
                .setValue(this.plugin.settings.clientScope)
                .onChange(async (value) => {
                    logInfo('clientScope: ' + value);

                    this.plugin.settings.clientScope = value || DEFAULT_SETTINGS.clientScope;
                    await this.plugin.saveSettings();

                    this.updateAuthLink(authLink);
                })
            })
        );

        apiConfigSettings.push(new Setting(contentEl)
            .setName('Google API redirect URI')
            .setDesc("Enter the Google API redirect URI to use. Leave blank to use the default URI which will require pasting the error URL from the browser back to the Obsidian app.")
            .addText(text => { text
                .setPlaceholder("Use default URI")
                .setValue(this.plugin.settings.redirectUri)
                .onChange(async (value) => {
                    logInfo('clientScope: ' + value);

                    this.plugin.settings.redirectUri = value || DEFAULT_SETTINGS.redirectUri;
                    await this.plugin.saveSettings();

                    this.updateAuthLink(authLink);
                })
            })
        );

        this.setGoogleCloudConfigurationVisible(apiConfigSettings, this.showGoogleCloudConfiguration);

        const authLink = contentEl.createEl('a', { text: '1. Click to log in to Google Drive' }) as HTMLAnchorElement;
        this.updateAuthLink(authLink);

        new Setting(contentEl)
            .setName('2. Paste Error URL')
            .setDesc('Paste here the error URL you get after clicking on the link above')
            .addText(text => text
                .setPlaceholder('Paste here URL from google drive error page')
                .setValue('')
                .onChange(async (value) => {
                    logInfo('errorUrl: ' + value);
                    const errorUrl = new URL(value);
                    // The normal expiration is 3600 seconds (one hour), the
                    // expiration will be renewed (a new token issued?) if the
                    // login page is used again before expiration
                    if (this.plugin.settings.clientSecret == '') {
                        // The url has the pattern
                        // http://localhost/#access_token=...&token_type=Bearer&expires_in=3598&
                        const authResult = new URLSearchParams(errorUrl.hash.substring(1));
                        logInfo("accessToken", authResult.get("access_token"));
                        this.plugin.settings.accessToken = authResult.get("access_token") || '';
                        this.plugin.settings.accessExpires = moment().add(authResult.get("expires_in"), 'second').format();
                    } else {
                        // The url has the pattern
                        // http://localhost/?code=...&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.file

                        // Exchange for a token
                        // Taken from oauth2 playground
                        const tokenParams = new URLSearchParams({
                            code: errorUrl.searchParams.get('code') as string,
                            redirect_uri: this.plugin.settings.redirectUri,
                            client_id: this.plugin.settings.clientId,
                            client_secret: this.plugin.settings.clientSecret,
                            scope: this.plugin.settings.clientScope,
                            grant_type: 'authorization_code',
                        });

                        // XXX When there are multiple clients using the same
                        //     clientid, secret and scope (eg the same user
                        //     accessing google drive from desktop and mobile)
                        //     only the first client will get the refresh token
                        //     (unless prompt is forced at code request time),
                        //     other clients will only get the same access
                        //     token. In standard OAuth2 you can use different
                        //     scopes per client in order to force different
                        //     tokens (and refresh tokens) per client, but
                        //     Google OAuth2 only allows Google scopes and using
                        //     a random scope returns validation error. Another
                        //     option is to use a server and keep the refresh
                        //     token in the server or in the google drive (but
                        //     that assumes the same sync folder)? See
                        //     https://developers.google.com/identity/protocols/oauth2/cross-client-identity
                        let resp = await fetch("https://oauth2.googleapis.com/token", {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: tokenParams
                        });
                        if (resp.status === 200) {
                            let jsonResp = await resp.json();
                            logInfo(jsonResp);
                            this.plugin.settings.accessToken = jsonResp.access_token;
                            this.plugin.settings.refreshToken = jsonResp.refresh_token;
                            this.plugin.settings.accessExpires = moment().add(jsonResp.expires_in, 'second').format();
                        } else {
                            logError("exchange code failed", resp.status, resp.statusText);
                            if (resp.headers.get("content-type") == "application/json; charset=UTF-8") {
                                logWarn("fetchApi error json", await resp.json());
                            }
                        }
                    }

                    await this.plugin.saveSettings();
                }));

        // XXX Store the error url so when the dialog box is popped up again
        //     it can be filled in

        // XXX Allow manually entering access token

        // XXX Allow different login methods (implicit, with client secret, with
        //     api key)

        const control = contentEl.createDiv("setting-item-control");
        control.style.justifyContent = "flex-start";

        // Ok and Cancel buttons are only shown when coming from fetchapi so
        // retries can be aborted, don't show them when coming Obsidian from
        // configuration since as a rule Obsidian configuration dialogs don't
        // have Ok and may be confusing since changes are applied
        // unconditionally even if Cancel is
        //
        // XXX Is this the right thing to do? Think about UX for Ok and Cancel
        if (this.showOkCancel) {
            new ButtonComponent(control)
                .setButtonText("Ok")
                .setCta()
                .onClick(() => {
                    logInfo("LoginModal Ok");
                    this.ok = true;
                    this.close();
                    // navigator.clipboard.writeText(this.currentVersionData);
            });
            new ButtonComponent(control)
                .setButtonText("Cancel")
                .onClick(() => {
                    logInfo("LoginModal Cancel");
                    this.close();
                    // navigator.clipboard.writeText(this.currentVersionData);
            });
        }
    }

    onClose() {
        logInfo("LoginModal.onClose", this.ok);
        const {contentEl} = this;
        contentEl.empty();
        this.resolve(this.ok);
    }
}

class GoogleDriveSettingsTab extends PluginSettingTab {
    plugin: GoogleDrive;
    parentIds: Array<string>;

    constructor(app: App, plugin: GoogleDrive) {
        super(app, plugin);
        this.plugin = plugin;
    }

    emptyDropdown(dropdown: DropdownComponent) {
        while (dropdown.selectEl.length > 0) {
            dropdown.selectEl.remove(0);
        }
    }

    populateFoldersDropdown(dropdown: DropdownComponent, parentId: string) {
        logInfo("populateFoldersDropdown", dropdown, parentId);

        // Empty and signal that the element is being populated
        this.emptyDropdown(dropdown);
        dropdown.addOption("<loading>", "<loading>");
        // If the dropdown is operated too quickly it can trigger several a
        // populate call before the previous one is done, which may result on
        // races depending on the server speed of each call, Disable the
        // dropdown until the population is done to prevent the races
        dropdown.setDisabled(true);
        let folders: Record<string, string> = {};

        if ((parentId == 'root') && this.plugin.settings.browseOrphans) {
            // XXX The orphans should be in their own subdirectory/sibling of My
            //     Drive so they don't collide with My Drive subfolders?
            this.fetchFolders(folders, null).then( () => {
                this.fetchFolders(folders, parentId).then( () => {
                    this.emptyDropdown(dropdown);
                    // XXX fetchFolders result is sorted but because of the two
                    //     calls, the folders are not sorted properly across
                    //     calls, fix?
                    // XXX Use [..] and [.] for consistency?
                    dropdown.addOption(".",".");
                    // XXX This should have some delete folder UI too?
                    dropdown.addOption("<new>", "<new>");
                    dropdown.addOptions(folders);
                    dropdown.setDisabled(false);
                });
            });
        } else {
            this.fetchFolders(folders, parentId).then( () => {
                this.emptyDropdown(dropdown);
                // XXX Use [..] and [.] for consistency?
                dropdown.addOption(".",".");
                dropdown.addOption("<new>", "<new>");
                if (parentId != 'root') {
                    dropdown.addOption("..", "..");
                }
                dropdown.addOptions(folders);
                dropdown.setDisabled(false);
            });
        }
    }

    async fetchFolders(folders: Record<string, string>, parentId: string|null, pageToken: string = '') {
        logInfo("fetchFolders", folders, parentId, pageToken);
        // XXX This can be called with an empty parentId when the folderId
        //     hasn't been chosen yet, verify it still works fine in that case?

        while (pageToken !== undefined) {

            // Show only folders, not in the trash and owned by the current user
            // XXX Note (not shared) and (not sharedWithMe) give invalid q errors
            // XXX Not clear restricting to not shared is strictly necessary but
            //     avoids having more complex checks to verify it can be written
            //     to? (also makes the query probably faster) But note if the
            //     sync mode is set to download only it won't need to write)
            // XXX Should this restrict to capabilities.canEdit/canAddChildren/canDelete...?
            //     See https://developers.google.com/drive/api/reference/rest/v3/files#File

            // XXX Note with v3 all of (not shared), ownedByMe, (not
            //     sharedWithMe), give errors, but ('me' in owners) works.
            //     See https://stackoverflow.com/questions/28500889/how-to-get-shared-with-me-files-in-google-drive-via-api
            //     Note (owner:me), owner:'me' are UI query parameters, not api
            //     query parameters
            let q = "(mimeType='application/vnd.google-apps.folder') and (not trashed) and ('me' in owners)"
            // Setting a parentid prevents from listing orphans (eg entries
            // under "Computers"), in order to list orphans provide a null
            // parentId and then filter out entries that have a parent field.
            // This can return lots of entries so there's a setting to disable
            // that. Another option is to use Total Commander's trick which is
            // forcing the user to add "Computer" anywhere in the name
            // See
            // https://stackoverflow.com/questions/64719294/google-drive-api-no-way-to-list-entries-under-computers
            // https://stackoverflow.com/questions/14025546/google-drive-api-list-files-with-no-parent
            // https://stackoverflow.com/questions/58136754/how-to-get-a-list-of-drive-files-that-are-orphaned

            // XXX Orphan folers also seem to have capabilities.canRename and
            //     not capabilities.canShare but the query q doesn't accept
            //     those?
            if (parentId != null) {
                q += " and ('" + parentId + "' in parents)";
            }
            const params = {
                q: q,
                // Fields can be files(*) to get all fields in the metadata
                fields: "nextPageToken, files(id, name, mimeType" + ((parentId == null) ? ", parents" : "") + ")",
                pageToken: pageToken,
                orderBy: "folder,name",
            };

            let resp = await this.plugin.fetchJson('drive/v3/files', params);
            logInfo(resp);
            resp.files.forEach((f: { id: string; name: string; mimeType: string; parents:string[]}) => {
                let name = f.name;
                if (f.mimeType == 'application/vnd.google-apps.folder') {
                    name = "[" + name + "]";
                }
                // If fetching orphans only push orphans (undefined f.parents)
                // Note the alias 'root' is only used as input, the output never
                // uses 'root' but the real id, so resp.parents cannot be
                // checked against 'root' once received
                if ((parentId != null) || (f.parents === undefined)) {
                    folders[f.id] = name;
                }
            });
            pageToken = resp.nextPageToken;
        }
    }

    updateDriveSetting(driveSetting: Setting, path:string) {
        // XXX Store the human readable path somewhere instead of
        //     recreating it everytime?
        const fragment = createFragment(fragment => {
            fragment.createSpan({ text: "Google Drive folder for this vault: "});
            fragment.createDiv({ text: path }, div => {
                div.style.color = 'var(--text-accent)';
            });
        });
        driveSetting.setDesc(fragment);
    }

    updateBrowseOrphansSetting(browseOrphansSetting: Setting) {
        logInfo("updateBroOrphansSetting", this.plugin.settings.clientScope);
        if (this.plugin.settings.clientScope == 'https://www.googleapis.com/auth/drive.file') {
            browseOrphansSetting.settingEl.hide();
        } else {
            browseOrphansSetting.settingEl.show();
        }
    }

    display(): void {
        const {containerEl} = this;

        containerEl.empty();

        containerEl.createEl("small", { text: "Created by "})
            .appendChild(createEl("a", { text: "Antonio Tejada", href:"https://github.com/antoniotejada/"}));

        containerEl.createEl('h3', {text: 'Account'});

        new Setting(containerEl)
            .setName("Google Drive login")
            .setDesc("Configure Google Drive login credentials")
            .addButton(button => button
                .setButtonText("Configure")
                .setCta()
                .onClick(async () => {
                    await new Promise((resolve, reject) => {
                        new LoginModal(this.plugin, false, resolve, reject).open();
                    });
                    const folderId = this.plugin.settings.folderId;
                    this.populateFoldersDropdown(folders, folderId);
                    this.updateBrowseOrphansSetting(browseOrphansSetting);
                })
            );

        containerEl.createEl('h3', {text: 'Synchronization'});


        const browseOrphansSetting = new Setting(containerEl)
            .setName("Include orphan root folders")
            .setDesc("Allow browsing Google Drive orphan root folders (eg \"Computers\") in the Google Drive folder dropdown. "+
                "If disabled, folders with an orphan root won't be available as Google Drive "+
                "folder to sync to, but filling the Google Drive dropdown when browsing the root level will be faster.")
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.browseOrphans)
                .onChange(async (value) => {
                    logInfo("Browse orphans: " + value);
                    this.plugin.settings.browseOrphans = value;
                    await this.plugin.saveSettings();

                    const folderId = this.plugin.settings.folderId;
                    // Only need to update the dropdown if root is shown.
                    // This means that orphan hierarchy can still be browsed
                    // if an orphan subfolder is currently being browsed,
                    // which is counterintuitive but ok
                    if (folderId == 'root') {
                        this.populateFoldersDropdown(folders, folderId);
                    }
            })
        );
        this.updateBrowseOrphansSetting(browseOrphansSetting);

        const driveSetting = new Setting(containerEl)
            .setName('Google Drive folder')
            .setDesc('Google Drive folder for this vault')
            .addDropdown(dropdown => dropdown
                .onChange(async (value) => {
                    logInfo("Google Drive folder: " + value);

                    if (value == ".") {
                        // This can happen when moving away from <new>, ignore

                    } else if (value == "<new>") {
                        // Request a folder name and create it within the
                        // current folderId

                        // XXX If cancelled it needs to move away from <new> to
                        //     ".", for now user can do it manually
                        new TextInputModal(this.app, "Create Google Drive folder", "Enter folder name", async (result) => {
                            // XXX Unify with regular folder switching path below? how to trigger an event passing value?
                            logInfo("Accepted TextInputModal", result);
                            const resp = await this.plugin.fetchCreateFolder(this.plugin.settings.folderId, result);
                            const folderId = resp.id;
                            this.parentIds.push(this.plugin.settings.folderId);

                            this.plugin.settings.folderId = folderId;

                            // Update the folder dropdown and the displayed full
                            // path
                            this.populateFoldersDropdown(folders, folderId);
                            this.plugin.fetchFolderPath(folderId).then(path => {
                                this.updateDriveSetting(driveSetting, path);
                            });
                            folders.selectEl.value = ".";

                            await this.plugin.saveSettings();
                        }).open();
                    } else {
                        let folderId;
                        if (value == "..") {
                            folderId = this.parentIds.pop() as string;
                        } else {
                            folderId = value;
                            this.parentIds.push(this.plugin.settings.folderId);
                        }
                        this.plugin.settings.parentIds = JSON.stringify({ids: this.parentIds});
                        this.plugin.settings.folderId = folderId;
                        this.populateFoldersDropdown(folders, folderId);

                        // Display the full path
                        this.plugin.fetchFolderPath(folderId).then( path => {
                            this.updateDriveSetting(driveSetting, path);
                        });
                    }
                    await this.plugin.saveSettings();
                })
        );

        let folders = driveSetting.components[0] as DropdownComponent;
        this.parentIds = new Array();

        if (this.plugin.settings.parentIds != '') {
            // Initialize parentIds from the json, this is necessary so the
            // combobox can go up in the path when operated
            // XXX This may be stale if the folder is moved around, fetch
            //     the path ids instead of storing in data.json?
            this.parentIds = JSON.parse(this.plugin.settings.parentIds).ids;
        }

        if (this.plugin.settings.accessToken != '') {
            const folderId = this.plugin.settings.folderId;
            this.populateFoldersDropdown(folders, folderId);
            if (folderId != '') {
                // Display the full path
                this.plugin.fetchFolderPath(folderId).then(path => {
                    this.updateDriveSetting(driveSetting, path);
                });
            }
        }

        if (false) {
            // XXX Missing implementing sync interval, should only Notice but not
            //     popup if login fails?

            new Setting(containerEl)
                .setName('Synchronization interval')
                .setDesc('Number of seconds between synchronizations to Google Drive. Set to empty to disable.')
                .addText(text => text
                    .setPlaceholder("Enter seconds to enable")
                    .setValue(this.plugin.settings.syncIntervalSecs)
                    .onChange(async (value) => {
                        logInfo('syncInterval: ' + value);
                        this.plugin.settings.syncIntervalSecs = value;
                        await this.plugin.saveSettings();
                    }
                )
            );
        }

        new Setting(containerEl)
            .setName("Synchronization mode")
            .setDesc("Only upload files, only download files, or both")
            .addDropdown(dropdown => dropdown
                .addOption("both", "Upload and download files")
                .addOption("upload", "Upload files only")
                .addOption("download", "Download files only")
                .setValue(this.plugin.settings.syncMode)
                .onChange(async (value) => {
                    logInfo("Sync mode: " + value);
                    this.plugin.settings.syncMode = value;
                    await this.plugin.saveSettings();
                }
            )
        );

        if (false) {
            // XXX Missing implementing compression, could use CompressionStream
            //     (Avail since Chrome v80)

            // XXX Compression needs to happen before encryption, but if gzip adds
            //     a deterministic header it should remove the header prior to encryption
            //     or it will weaken the encryption

            // XXX This may not need an ok as long as we can detect files that were
            //     compressed
            // XXX Have a compression blacklist?

            // XXX This could also offer to compress the whole vault in a single zip
            //     file which could solve issues but then uploading would be slower?
            new Setting(containerEl)
                .setName("Compress files")
                .setDesc("Store files compressed in Google Drive")
                .addToggle(toggle => toggle
                    .setValue(this.plugin.settings.compressFiles)
                    .onChange(async (value) => {
                        logInfo("Compress files: " + value);
                        this.plugin.settings.compressFiles = value;

                        await this.plugin.saveSettings();
                })
            );
        }

        // XXX Have an option to allow synchronizing the hidden .obsidian folder?
        //     Will require using the adapter API instead of the vault API and
        //     it shouldn't sync the workspace.json and other files?

        // XXX Having blacklist of folders/files not to sync, eg starting with
        //     ".", .edtz...

        // XXX Allow watching changes

        // XXX Add setting for nr of login retries?

        if (false) {

            containerEl.createEl("h3", {text: "File encryption"});

            // XXX Missing implementing encryption
            //     See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
            //     See https://stackoverflow.com/questions/45636545/webcrypto-string-encryption-using-user-submitted-password
            //     See https://github.com/bradyjoslin/webcrypto-example
            // XXX This needs an OK button so the files are encrypted/decripted
            //     when the password is changed:
            //     - Only allow changing encryption on empty Google Drive?
            //     - Force a sync on password change and then a re-upload? (this
            //     doesn't work when the password is updated first in one client and
            //     then on another). Most javascript standard cyphers will detect
            //     when the key is wrong, so it could treat the decryption as a
            //     failed download? what about uploads in theory it wouldn't upload
            //     since there are no local changes?
            //     - No sync, just warn this will cause a re-upload? What about
            //     clients with the password out of date, won't be able to read and
            //     will get all overwritten which should be what it's intended?
            //     (unless filenames are encrypted too)
            // XXX Another option is to add jszip with encryption which will do
            //     compression and encryption and using a standard
            //     See https://github.com/Stuk/jszip/pull/696
            //     See https://www.winzip.com/en/support/aes-encryption/
            new Setting(containerEl)
                .setName('Password')
                .setDesc("Store files encrypted in Google Drive using this password, leave blank for no encryption.")
                .addText(text => {
                    text
                    .setPlaceholder("Enter password to enable")
                    .setValue(this.plugin.settings.encryptionPassword)
                    .onChange(async (value) => {
                        logInfo('password: ' + value);
                        this.plugin.settings.encryptionPassword = value;

                        await this.plugin.saveSettings();
                    })
                    .inputEl.type = "password";
                    text.inputEl.style.flexGrow = '1';
                })
                .addButton(button => {
                    button
                    .setIcon("eye")
                    .onClick(() => {
                        const inputEl = button.buttonEl.previousElementSibling as HTMLInputElement;
                        const isPassword = (inputEl.type == "text");
                        inputEl.type = isPassword ? "password" : "text";
                        button.setIcon(isPassword ? "eye" : "eye-off");
                    })
                    // XXX This is to prevent the button from taking half the size
                    //     of the parent on Android but it doesn't seem to do
                    //     anything?
                    .buttonEl.style.flexGrow = '0';
                });

            // XXX This needs an OK so the files are encrypted/decripted when the
            //     password is changed
            new Setting(containerEl)
                .setName("Encrypt filenames")
                .setDesc("Encrypt the filenames as well as the file contents.")
                .addToggle(toggle => toggle
                    .setValue(this.plugin.settings.encryptFilenames)
                    .onChange(async (value) => {
                        logInfo("Encrypt filenames: " + value);
                        this.plugin.settings.encryptFilenames = value;

                        await this.plugin.saveSettings();
                })
            );
        }

        containerEl.createEl("h3", {text: "Debugging"});

        new Setting(containerEl)
            .setName("Debug level")
            .setDesc("Messages to show in the javascript console.")
            .addDropdown(dropdown => dropdown
                .addOption("error", "Errors")
                .addOption("warn", "Warnings")
                .addOption("info", "Information")
                .addOption("debug", "Verbose")
                .setValue(this.plugin.settings.debugLevel)
                .onChange(async (value) => {
                    logInfo("Debug level: " + value);
                    this.plugin.settings.debugLevel = value;
                    await this.plugin.saveSettings();
                }));
    }
}
