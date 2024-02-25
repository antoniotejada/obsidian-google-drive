# Obsidian Google Drive Plugin

[Obsidian](https://obsidian.md) plugin that allows synchronizing vaults from and to your [Google Drive](https://www.google.com/drive/) account.

There are other ways of synchronizing Obsidian vaults to Google Drive but they require installing third party apps, while this is a standalone native Obsidian implementation.

**Note there's no deletion/renaming support yet, also there's no conflict detection warning either, ie if you modify a vault from two different devices without synchronizing to Google Drive and then synchronize both to Google Drive, the oldest modification will be overwritten without warning on both the local vaults and Google Drive. See [TODO](#todo)**

## Features
- Google OAuth2 secure Google Drive authorization
- No third party server access other than Google Drive
- One hour Google Drive login timeout, if you synchronize your Obsidian vault with Google Drive after the timeout you will be prompted to login again (this is a limitation of not using third party servers, may change in the future)
- Google Drive folder creation/browsing to synchronize the Obsidian vault to
- Synchronize Obsidian vault from/to Google Drive
  - Upload files/folders from Obsidian vault to Google Drive
  - Download files/folders from Google Drive to Obsidian vault
  - Overwrite older files in Obsidian vault or Google Drive with the newer ones
  - _Upload only_, _download only_, _upload and download_ synchronization modes
- With the plugin's default configuration settings, Google Drive access is limited to files and folders created by this plugin, can't access the rest of your Google Drive
- Android support (untested on iOS, may work)
- PC support (untested on Mac, may work)
- Supports personalized Google Cloud API settings, when using those:
  - Supports all Google Drive access (not just files and folders created by this plugin)
  - Supports Google Drive _Computer_ folders (ie orphan folders)
  - Supports Google Drive transparent token refresh after the one hour Google Drive login timeout

## Usage

### First Obsidian vault instance

1. Create and populate a vault inside Obsidian as usual or use an existing vault
1. Configure Google Drive Plugin settings, specifically
    1. Configure Google Drive login
        1. Leave the default settings, click on the _Click to login to Google Drive_ link.
        1. A browser window using your default browser will open requiring your user and password to access Google Drive on behalf of _Obsidian Google Drive Plugin_
        1. After filling in your password and accepting, you will be redirected to an error URL that starts with _localhost:_, copy that whole URL
        1. Go back to Obsidian Google Drive login dialog box and paste that URL into the _Paste error URL_ text box and press Ok
    1. Now that you have configured Google Drive login, create a Google Drive folder for your vault by choosing _\<new>_ in the _Google Drive folder_ dropdown
        1. Enter the folder name in the dialog box
        1. The dropdown will update and the folder is now your Google Drive vault folder
1. Configure the rest of the Google Drive Plugin settings as desired and dismiss the configuration dialog
1. Manually synchronize the vault with Google Drive whenever needed by pressing the _Synchronize Vault to Google Drive_ ribbon icon or the command _Google Drive: Synchronize vault_
1. Edit your notes as usual, synchronize with Google Drive as desired

### Second and later Obsidian vault instances
1. Create an empty vault inside Obsidian
1. Configure the plugin settings as with the [first instance](#first-obsidian-vault-instance) but choose an existing Google Drive folder instead of creating a new one.
1. Manually synchronize the vault with Google Drive by pressing the _Synchronize Vault to Google Drive_ ribbon icon or the command _Google Drive: Synchronize vault_, this will download all the files in that Google Drive folder into your Obsidian vault
1. Edit your notes as usual, synchronize with Google Drive as desired

## Google Drive login settings

### Default Google Drive login settings

The default settings have the following limitations:
  - Can only access files and folders created from the plugin.
  - Will periodically timeout and force to enter username and password in the browser to re-authorize the plugin

### Personalized Google Drive login settings

If you have your own Google Cloud developer account, you can use your own settings (client id, secret, scope and uri) in the Google Drive login configuration and
- Bypass the one hour limit
- Access your whole Google Drive if you use a drive scope

## Privacy

The plugin doesn't collect any kind of information, Google may collect whatever default statistics Google Cloud collects when you authorize applications to access and operate Google Drive.

The plugin doesn't communicate to any server other than Google's to access your Google Drive files.

The default (non personalized) settings only have access to files and folders created by this plugin.


## TODO
- ~~Support file/folder deletion~~
- ~~Support file/folder renaming~~
- Support periodic syncs
- Add support for synchronizing metadata (e.g. `.obsidian` directory)
- Support conflict detection
- Support encryption
- Support compression
- Support for >5MB files
- Better error checking
