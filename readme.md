## mDNSShark

mDNSShark is an **open-source** iPhone application, created by a small team of engineers who wanted a simpler, clearer way to explore local networks. By tapping into protocols like Multicast DNS (mDNS), DNS-SD, and SSDP, mDNSShark quickly uncovers printers, media servers, IoT gadgets, and other active services on your home or office Wi-Fi-no convoluted setup required. If you’ve ever wondered what devices are really on your network, or how various services talk to each other, mDNSShark is designed to give you those answers efficiently and privately.

## Simplicity and Privacy  

Simplicity is key: we’ve stripped away clutter so you can focus on scanning and understanding results. Every discovery operation runs right on your phone, with **no external servers** involved. We also do **not** collect or share any usage data-there’s no telemetry, no user analytics, and certainly no hidden trackers. You remain fully in control, deciding if and when to allow local network access, which is all the app needs to function.

## Built by Engineers, Open to Everyone  

mDNSShark was created by engineers who love transparent, lightweight solutions-yet it’s also friendly for anyone curious about local network behavior. If you’re a fellow engineer, a technologist, or just someone who enjoys problem-solving, you’ll find plenty of ways to contribute. Newcomers can help refine the interface, add new features, or even propose deeper networking enhancements. Veterans can dive into advanced scanning logic, integrate emergent protocols, and optimize performance. We firmly believe that collectively, we can build an indispensable network tool for iPhone users everywhere.

## Current Development  

mDNSShark is still **in active development**, with regular updates that refine performance, expand support for various network protocols, and polish the user experience. We welcome your ideas-whether it’s a new device detection trick, an easier UI flow, or an innovative scanning feature. Our public repository provides a transparent view of current issues and ongoing discussions, letting you jump in wherever your skills or interests fit best.

## Core Features at a Glance  

- **Bonjour/mDNS (DNS-SD)**: Identifies devices like AirPlay receivers, printers, or file-sharing services through built-in discovery.  
- **SSDP**: Finds devices that speak UPnP, such as smart TVs or internet gateways.  
- **Local Subnet Scans**: Optionally scans the /24 subnet to uncover common TCP-based services, even if they aren’t broadcasting via Bonjour or SSDP.  
- **OUI Lookups**: Matches a device’s MAC-like address to manufacturers, giving quick hardware insights.  
- **Minimalist Interface**: Straight to the point-run a scan, view your devices, dig into details as needed.  

## System Requirements  

1. **Device**: iPhone only.  
2. **iOS Version**: **iOS 14 or later** for access to modern SwiftUI and networking APIs.  
3. **Network**: A reliable Wi-Fi connection is recommended for full scanning capabilities.  
4. **Development (Optional)**: To build or modify the code, you’ll need **Xcode 12 or above** and Swift 5.3 or later.  

## Contribute and Collaborate  

We’re always eager for fresh ideas and extra sets of eyes on the code:  

- **Open Issues**: Let us know if you spot bugs or would like a new feature.  
- **Pull Requests**: Share your improvements or experiments with the community.  
- **Discussions**: Suggest changes, ask questions, or explore new scanning methods.  

mDNSShark is grounded in the principle that local network exploration doesn’t have to be intimidating-or invasive. We’re building a community-driven tool that emphasizes clarity, privacy, and inclusivity, so anyone can understand and troubleshoot what’s happening on their own network. Whether you’re an experienced developer or just love tinkering, mDNSShark can use your passion and expertise.  

Join us to help shape the future of straightforward, on-device network discovery -**no data collection, no lengthy setups, just powerful scanning for everyone.**

