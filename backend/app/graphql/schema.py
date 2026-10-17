"""
AegisHMAC Protected GraphQL Engine (Strawberry GraphQL).
Demonstrates requirement FR7: Authenticating GraphQL queries and mutations over HTTP POST
with identical cryptographic integrity guarantees as REST APIs.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info


@strawberry.type
class Account:
    """GraphQL type representing a financial account."""
    id: str
    client_id: str
    balance: float
    currency: str
    status: str


@strawberry.type
class Transaction:
    """GraphQL type representing a transaction record."""
    id: str
    from_account: str
    to_account: str
    amount: float
    currency: str
    status: str
    created_at: str


@strawberry.type
class TransferResult:
    """GraphQL result type for transfer mutations."""
    success: bool
    transaction_id: str
    message: str
    remaining_balance: float


# -----------------------------------------------------------------------------
# GraphQL Queries & Mutations
# -----------------------------------------------------------------------------

@strawberry.type
class Query:
    """Root GraphQL Query definition."""

    @strawberry.field
    def get_account(self, info: Info, account_id: str) -> Account:
        """Fetch account balance for the authenticated client."""
        request = info.context["request"]
        client_id = getattr(request.state, "client_id", "anonymous")

        return Account(
            id=account_id,
            client_id=client_id,
            balance=15420.50,
            currency="USD",
            status="ACTIVE",
        )

    @strawberry.field
    def list_transactions(self, info: Info, limit: int = 5) -> List[Transaction]:
        """List recent transactions for the authenticated client."""
        request = info.context["request"]
        client_id = getattr(request.state, "client_id", "anonymous")
        now = datetime.now(timezone.utc).isoformat()

        return [
            Transaction(
                id=f"tx_{i+1}",
                from_account=f"acc_{client_id}",
                to_account=f"acc_vendor_{i+100}",
                amount=round(50.0 * (i + 1), 2),
                currency="USD",
                status="COMPLETED",
                created_at=now,
            )
            for i in range(min(limit, 10))
        ]


@strawberry.type
class Mutation:
    """Root GraphQL Mutation definition."""

    @strawberry.mutation
    def execute_transfer(
        self,
        info: Info,
        from_account: str,
        to_account: str,
        amount: float,
        currency: str = "USD",
    ) -> TransferResult:
        """
        Execute funds transfer via GraphQL mutation.
        The entire GraphQL query string and variables are cryptographically hashed,
        preventing any tampering with amount or accounts.
        """
        request = info.context["request"]
        client_id = getattr(request.state, "client_id", "anonymous")
        tx_id = f"tx_gql_{uuid.uuid4().hex[:10]}"

        return TransferResult(
            success=True,
            transaction_id=tx_id,
            message=f"Successfully transferred {amount} {currency} from {from_account} to {to_account} for {client_id}",
            remaining_balance=round(15420.50 - amount, 2),
        )


schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_app = GraphQLRouter(schema)
