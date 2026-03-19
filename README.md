# govauth

GovAuth prototype repository.

## Happy Path

Current goal:

- 创建并发布一个Policy
- 基于Policy派生一个Enforcement Plan
- 创建一个Execution Session
- 提交一份Evidence
- 生成一个Pinned Snapshot
- 执行一次Evaluation
- 生成一个Artifact


## APP On
go mod tidy  
go build ./cmd/server  

make happy   
make deny  
make invalid  