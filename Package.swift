// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "FountainStoreHostEnrollmentKit",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "FountainStoreHostEnrollmentKit", targets: ["FountainStoreHostEnrollmentKit"])
    ],
    targets: [
        .target(name: "FountainStoreHostEnrollmentKit"),
        .testTarget(name: "FountainStoreHostEnrollmentKitTests", dependencies: ["FountainStoreHostEnrollmentKit"])
    ]
)
