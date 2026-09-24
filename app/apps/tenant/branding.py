"""
Branding and UI customization schemas.

This module defines schemas for tenant branding including colors,
typography, and logos.
"""

from typing import Annotated

from pydantic import BaseModel, StringConstraints


class ShapeSchema(BaseModel):
    """
    Shape configuration schema.

    Attributes:
        borderRadius: Border radius value for UI elements.

    """

    borderRadius: int | None = None  # ruff:ignore[mixed-case-variable-in-class-scope]


class PaletteColorSchema(BaseModel):
    """
    Color palette schema for a single color.

    Attributes:
        main: Main color in hex format.
        light: Light variant of the color.
        dark: Dark variant of the color.
        contrastText: Contrast text color for accessibility.

    """

    main: Annotated[
        str,
        StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$"),
    ]
    light: (
        Annotated[
            str,
            StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$"),
        ]
        | None
    ) = None
    dark: (
        Annotated[
            str,
            StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$"),
        ]
        | None
    ) = None
    contrastText: (  # ruff:ignore[mixed-case-variable-in-class-scope]
        Annotated[
            str,
            StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$"),
        ]
        | None
    ) = None


class PaletteSchema(BaseModel):
    """
    Color palette schema.

    Attributes:
        primary: Primary color palette.
        secondary: Secondary color palette.

    """

    primary: PaletteColorSchema = PaletteColorSchema(main="#dddddd")
    secondary: PaletteColorSchema = PaletteColorSchema(main="#aaaaaa")


class TypographySchema(BaseModel):
    """
    Typography configuration schema.

    Attributes:
        fontFamily: Font family name.
        fontSize: Base font size.
        allVariants: Dictionary of font variants.

    """

    fontFamily: str | None = None  # ruff:ignore[mixed-case-variable-in-class-scope]
    fontSize: int = 14  # ruff:ignore[mixed-case-variable-in-class-scope]
    allVariants: dict[str, str] = {}  # ruff:ignore[mixed-case-variable-in-class-scope]


class BrandingSchema(BaseModel):
    """
    Complete branding configuration schema.

    Attributes:
        logo: Logo URL or path.
        favicon: Favicon URL or path.
        title: Brand title.
        description: Brand description.
        shape: Shape configuration.
        palette: Color palette configuration.
        typography: Typography configuration.

    """

    logo: str | None = None
    favicon: str | None = None
    title: str | None = None
    description: str | None = None
    shape: ShapeSchema | None = None
    palette: PaletteSchema = PaletteSchema()
    typography: TypographySchema | None = None


class BrandingModel(BaseModel):
    """
    Simplified branding model for tenant configuration.

    Attributes:
        primary_color: Primary brand color in hex format.
        secondary_color: Secondary brand color in hex format.
        font_family: Font family for UI.
        logo: Logo URL.
        favicon: Favicon URL.
        custom_css: Custom CSS for additional styling.

    """

    primary_color: str = "#000000"
    secondary_color: str = "#ffffff"
    font_family: str = "system-ui"
    logo: str = "https://media.usso.io/usso.svg"
    favicon: str | None = None
    custom_css: str | None = None
