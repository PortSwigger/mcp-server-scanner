package com.mcpscanner.checks.catalog.oauthconsentstructurereflection;

record FieldReflection(ReflectedField field, StructureMarker marker, StructurePlacement placement) {

    String parsedName() {
        return placement == StructurePlacement.ELEMENT ? marker.elementName() : marker.attributeName();
    }
}
