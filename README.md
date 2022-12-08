## user-manifest

User-manifest is a tool for evaluating/tracking user permissions in a k8s cluster. It essentially exists to answer questions like:

- Which permissions does user x have?
- Why does user x have y permission?
- Who has access to role x in namespace y?
- Who has access to cluster-role y?

While each of these questions could be answered through various kubectl commands, this project aims to give quick, reliable, and comprehensive answers to the questions above. This can enable things like a permission tracking UI or regular user reports/alerts which would have been difficult to produce without such a solution.