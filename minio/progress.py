from typing import Protocol


class Progress(Protocol):
    def set_meta(self, total_length: int, object_name: str) -> None:
        """
        Metadata settings for the object. This method called before uploading
        object
        :param total_length: Total length of object.
        :param object_name: Object name to be showed.
        """

    def update(self, size: int) -> None:
        """
        Update object size to be showed. This method called while uploading
        :param size: Object size to be showed. The object size should be in
                     bytes.
        """
