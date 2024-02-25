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
    Modal,
    moment,
    Notice,
    Plugin,
    Setting,
    TFolder,
    TFile,
	TAbstractFile,
} from 'obsidian';

import { GoogleDriveSettings, IGoogleDrive, GoogleDriveFile, GoogleDriveFileList } from 'types';
import { DEFAULT_SETTINGS, GoogleDriveSettingsTab, LoginModal } from './settings';
import { hookLogFunctions, DEBUG_LEVELS, logInfo, logWarn, logError } from 'debug';

hookLogFunctions(DEBUG_LEVELS.indexOf("debug"), "GoogleDrive");

export default class GoogleDrive extends Plugin implements IGoogleDrive {
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

	// A queue of paths to be deleted.
	deleteQueue: Array<string> = [];

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
			this.deleteQueue.push(abstractFile.path);
			logInfo("added to delete queue: ", abstractFile.path);
		});

		// We treat renames as a deletion operation, followed by a create operation.
		this.app.vault.on('rename', (abstractFile: TAbstractFile, oldPath: string) => {
			// Add the old path to the delete queue.
			this.deleteQueue.push(oldPath);
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
        hookLogFunctions(DEBUG_LEVELS.indexOf(settings.debugLevel), "GoogleDrive");

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
				let nextPathToDelete = this.deleteQueue.pop();
				// let abstractFilePaths = nextAbstractFileToDelete?.path.split("/");
				// console.log("***** DEBUG_jwir3: abstract file path of deletion target: ", abstractFilePaths);
				let searchResults: GoogleDriveFileList = await this.findFolderByRelativePath(nextPathToDelete, this.settings.folderId);
				// Retrieve the id from the first result, if it's found
				if (searchResults.files.length > 0) {
					let resultingFile = searchResults.files[0];
					await this.deleteFile(resultingFile.id);
				}
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
