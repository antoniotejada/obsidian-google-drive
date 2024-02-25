import { Plugin, TAbstractFile } from "obsidian";

export interface GoogleDriveSettings {
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

export interface IGoogleDrive extends Plugin {
	settings: GoogleDriveSettings;

    accessToken: string | null;
    maxLoginRetries: number;

    downloadChanges: boolean;
    uploadChanges: boolean;

    loginPromise: Promise<boolean> | null;
    refreshPromise: Promise<Response> | null;

    // 0 no sync, positive nonzero sync, negative filtered out beforehand.
    // Initialized to zero to force toggle if enabled in the configuration
    syncIntervalSecs: number;
    syncIntervalId: number | null;

	deleteQueue: Array<TAbstractFile>;

	fetchJson(endpoint: string, params: any, init: RequestInit|null) : Promise<any>;
	fetchCreateFolder(parentId: string, folderName: string): Promise<any>;
	fetchFolderPath(folderId: string): Promise<string>;

	saveSettings(): void;
	loadSettings(): void;
}

export type GoogleDriveFile = {
    id: string;
    name: string;
    mimeType: string;
    // In RFC 3339 date-time format, can be used as Date(string),
    // Date.parse(string)
    modifiedTime: string;
    createdTime: string;
};

export type GoogleDriveFileList = {
	incompleteSearch: boolean;

	files: GoogleDriveFile[];
}
