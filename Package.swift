// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "FountainStoreHostEnrollmentKit",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "FountainStoreHostEnrollmentKit", targets: ["FountainStoreHostEnrollmentKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(name: "FountainStoreHostEnrollmentKit", dependencies: [
            .product(name: "Crypto", package: "swift-crypto")
        ]),
        .testTarget(name: "FountainStoreHostEnrollmentKitTests", dependencies: ["FountainStoreHostEnrollmentKit"])
    ]
)
