from box_sdk_gen import *
import os

class BoxConnection:
    """Class for connecting to Box, reading files, uploading files and getting names of files."""
    def __init__(self, auth_code):
        self.auth_code = None
        self.auth = None
        self.client = None
        self.update_auth(auth_code)

    def update_auth(self, auth_code):
        """Connect to box with a given authentication code"""
        self.auth_code = auth_code
        self.auth: BoxDeveloperTokenAuth = BoxDeveloperTokenAuth(token=self.auth_code)
        self.client: BoxClient = BoxClient(auth=self.auth)

    def upload_file(self, path, output_path=None):
        """Uploads a file located at path to box"""
        # TODO: chunked
        if not output_path:
            output_path = path

        with open(path, 'rb') as file_content_stream:
            self.client.uploads.upload_file(
                UploadFileAttributes(name=output_path, parent=UploadFileAttributesParentField(id="0")),
                file_content_stream
            )

    def get_all_files(self):
        """Returns a list of all filenames in the box"""
        return self.client.folders.get_folder_items('0').entries






