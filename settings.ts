import {
    App,
	ButtonComponent,
    DropdownComponent,
	Modal,
	moment,
	Plugin,
    PluginSettingTab,
    Setting,
} from 'obsidian';

import { IGoogleDrive, GoogleDriveSettings } from 'types';
import { logInfo, logWarn, logError } from 'debug';

export const DEFAULT_SETTINGS: GoogleDriveSettings = {
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

export class GoogleDriveSettingsTab extends PluginSettingTab {
    plugin: IGoogleDrive;
    parentIds: Array<string>;

    constructor(app: App, plugin: IGoogleDrive) {
        super(app, plugin);
        this.plugin = plugin as IGoogleDrive;
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

            let resp = await this.plugin.fetchJson('drive/v3/files', params, null);
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

export class LoginModal extends Modal {
    plugin: IGoogleDrive;
    resolve: any;
    reject: any;
    ok: boolean;
    showGoogleCloudConfiguration: boolean = false;
    showOkCancel: boolean;

    constructor(plugin: IGoogleDrive, showOkCancel: boolean, resolve: any, reject: any) {
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
