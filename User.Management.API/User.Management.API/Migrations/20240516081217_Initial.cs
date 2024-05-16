using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.API.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "073e8a0f-f22e-4e67-ab69-69135bd53a14");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "0e2377d0-8bd6-423d-b8b0-7054dfefcc75");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "323d29f4-a146-4075-92a9-0025e385a2bc");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "3bb77e4e-081a-4969-96d0-5a1b72d5f115", "3", "HR", "HR" },
                    { "908919ac-de66-4712-9a9e-098f0b8c191d", "2", "User", "User" },
                    { "972ced24-2e49-43ae-bad7-e13806108de3", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3bb77e4e-081a-4969-96d0-5a1b72d5f115");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "908919ac-de66-4712-9a9e-098f0b8c191d");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "972ced24-2e49-43ae-bad7-e13806108de3");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "073e8a0f-f22e-4e67-ab69-69135bd53a14", "2", "User", "User" },
                    { "0e2377d0-8bd6-423d-b8b0-7054dfefcc75", "3", "HR", "HR" },
                    { "323d29f4-a146-4075-92a9-0025e385a2bc", "1", "Admin", "Admin" }
                });
        }
    }
}
