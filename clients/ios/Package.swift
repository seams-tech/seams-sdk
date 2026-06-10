// swift-tools-version: 5.10

import PackageDescription

let package = Package(
  name: "SeamsIOS",
  platforms: [
    .iOS(.v16),
  ],
  products: [
    .library(name: "SeamsIOS", targets: ["SeamsIOS"]),
  ],
  targets: [
    .target(name: "SeamsIOS"),
    .testTarget(name: "SeamsIOSTests", dependencies: ["SeamsIOS"]),
  ]
)
