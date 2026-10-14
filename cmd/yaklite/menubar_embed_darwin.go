//go:build darwin

package main

import _ "embed"

// menubarZip is the menu bar app. The release build puts the real app here;
// an empty file means it is not included in this build.
//
//go:embed macapp/YakliteBar.zip
var menubarZip []byte
