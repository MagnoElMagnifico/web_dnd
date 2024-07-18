import re
from pathlib import Path
from http import HTTPStatus


class TemplateFormatError(Exception):
    """The format of the template is invalid."""


def filepath_from_url(url: str, base: Path) -> Path:
    """Returns a valid filepath from a URL, relative to `base`"""

    # If the URL starts with '/', the base path will be ignored.
    if url.strip()[0] == "/":
        url = url.strip()[1:]

    # Get the relative filepath
    filepath = base / url
    # Now get the absolute representation and resolve symlinks
    filepath = filepath.absolute().resolve()

    if not filepath.exists() or filepath.is_dir():
        raise FileNotFoundError(f'"{url}" could not be found')

    # Avoid Directory Path Traversal
    if base not in filepath.parents:
        raise FileNotFoundError(f'"{url}" is not under "{base}"')

    return filepath


class TemplateEngine:
    def __init__(self, template_dir: Path) -> None:
        assert isinstance(template_dir, Path), "template_dir must be a pathlib.Path"
        self.template_dir = template_dir

        # Compile regex
        self.template_indicator = re.compile(
            r".*{{\s*template:(base|.*\.html)\s*}}.*",
            flags=re.DOTALL,
        )

        self.block_definition = re.compile(
            r"{{\s*block\s*\"(.*?)\"\s*}}(.*?){{\s*/\s*block\s*}}",
            flags=re.DOTALL,
        )

        self.define_statement = re.compile(
            r"{{\s*define\s*\"(.*?)\"\s*}}|{{\s*template:(base)\s*}}",
        )

        self.error_values = re.compile(r"{{\s*(code|description|phrase)\s*}}")

    def get_template_indicator(self, filename: Path | str) -> str | None:
        with open(filename, "r") as template:
            # Get an iterator over file lines
            line_iter = iter(template)

            # Skip any blank lines
            first_line = next(line_iter)
            while first_line.strip() == "":
                first_line = next(line_iter)

            # Get the template indicator
            template_name, number_of_subs = self.template_indicator.subn(
                r"\1",
                first_line,
                count=1,
            )

            if number_of_subs != 1:
                return None

            return template_name

    def process_html(self, filename: Path | str) -> str:
        filename = self.template_dir / filename
        template_filename = self.get_template_indicator(filename)

        if template_filename is None:
            raise TemplateFormatError(f'Template indicator not found in "{filename}"')

        if template_filename == "base":
            raise TemplateFormatError(
                f'Cannot process HTML "{filename}" because it is of type "base"'
            )

        # Read base template
        template_filename = self.template_dir / template_filename
        if self.get_template_indicator(template_filename) != "base":
            raise TemplateFormatError(
                f'Invalid base template: "{template_filename}", "base" expected (recursive templates are not supported)'
            )

        # Read html contents
        html_content = filename.read_text()
        blocks = self.block_definition.findall(html_content)

        # Create a map to easily connect the block title with its content
        block_map = {block_name: block_content for block_name, block_content in blocks}

        # Replace define sentences with the block content
        return self.define_statement.sub(
            # The second capture group is used to remove the template indicator
            lambda matchobj: (
                block_map[matchobj.group(1)]
                if matchobj.group(2) != "base" and matchobj.group(1) in block_map
                else ""
            ),
            template_filename.read_text(),
        )

    def error_html(self, filename: Path | str, status: HTTPStatus) -> str:

        def map_values(matchobj: re.Match) -> str:
            match matchobj.group(1):
                case "code":
                    return str(status.value)
                case "description":
                    return status.description
                case "phrase":
                    return status.phrase
                case other:
                    raise ValueError(f'Unreachable: "{other}"')

        return self.error_values.sub(map_values, self.process_html(filename))
